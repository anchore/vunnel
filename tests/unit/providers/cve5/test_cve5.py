import glob
import hashlib
import io
import os
import tarfile
import time
from unittest.mock import MagicMock

import jsonschema
import orjson
import pytest
import requests
import zstandard

from vunnel import result, workspace
from vunnel.cli import config
from vunnel.providers import cve5
from vunnel.providers.cve5 import manager

FIXTURES = os.path.join(os.path.dirname(__file__), "test-fixtures")

# records from the 2026-10-21 publish. CVE-2022-35990 fails the CVE 5 schema, so it is packed only where a test asks for it.
INVALID = "CVE-2022-35990.json"
RECORD_FILES = sorted(p for p in glob.glob(os.path.join(FIXTURES, "CVE-*.json")) if os.path.basename(p) != INVALID)
MANIFEST_URL = "https://example.test/cve5/v5/latest.json"
ARCHIVE_PATH = "2026/10/cve-enriched-json-v5_2026-10-21T11:19:58Z.tar.zst"
ARCHIVE_URL = "https://example.test/cve5/v5/" + ARCHIVE_PATH
# the checksum the publish's own manifest carries, which no test-built archive matches
PUBLISHED_CHECKSUM = "sha256:d4b5ae7cd3f08e33592f71c6b88ede624b2a95668d07f49adb3f2e0672d30e08"


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _path_in_publish(name: str) -> str:
    # CVE-2026-85091.json -> data/2026/85/CVE-2026-85091.json
    year, num = name.removesuffix(".json").split("-")[1:]
    return f"data/{year}/{num[:-3] or num[0]}/{name}"


def make_archive(
    exclude: tuple[str, ...] = (),
    include: tuple[str, ...] = (),
    layout=_path_in_publish,
    replace: dict[str, bytes] | None = None,
    records: bool = True,
) -> bytes:
    """pack the fixtures as a tar.zst: records, plus a file that is not a record."""
    replace = replace or {}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        members = {"README.md": b"# enriched CVE 5\n"}
        if records:
            for path in RECORD_FILES + [os.path.join(FIXTURES, n) for n in include]:
                name = os.path.basename(path)
                if name in exclude:
                    continue
                members[layout(name)] = replace.get(name, _read(path))
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return zstandard.ZstdCompressor().compress(buf.getvalue())


def manifest_for(archive: bytes) -> dict:
    return {"status": "active", "built": "2026-10-20T13:54:00Z", "path": ARCHIVE_PATH, "checksum": "sha256:" + hashlib.sha256(archive).hexdigest()}


def _response(payload: bytes) -> MagicMock:
    response = MagicMock(status_code=200, iter_content=lambda chunk_size=None: [payload])  # noqa: ARG005
    response.json.side_effect = lambda: orjson.loads(payload)
    response.__enter__.return_value = response
    return response


@pytest.fixture
def serve(mocker):
    """patch the http layer so the provider gets the manifest and archive below instead of using the network. returns the list of requested urls and kwargs."""
    calls = []
    state = {"manifest": b"", "archive": b"", "errors": {}}

    def fake_get(url, logger, **kwargs):  # noqa: ARG001
        calls.append((url, kwargs))
        if url in state["errors"]:
            raise state["errors"][url](url)
        return _response(state["manifest"] if url.endswith("latest.json") else state["archive"])

    mocker.patch("vunnel.utils.http_wrapper.get", side_effect=fake_get)
    mocker.patch.object(time, "sleep")

    def configure(archive: bytes | None = None, manifest: dict | bytes | None = None, errors: dict | None = None):
        """serve `archive` with a matching manifest unless `manifest` overrides it."""
        if archive is not None:
            state["archive"] = archive
            manifest = manifest_for(archive) if manifest is None else manifest
        if manifest is not None:
            state["manifest"] = manifest if isinstance(manifest, bytes) else orjson.dumps(manifest)
        state["errors"] = errors or {}
        return calls

    configure.calls = calls
    return configure


def new_provider(helpers, store=result.StoreStrategy.SQLITE, **cfg):
    ws = helpers.provider_workspace_helper(name=cve5.Provider.name())
    p = cve5.Provider(root=ws.root, config=cve5.Config(url=MANIFEST_URL, **cfg))
    p.config.runtime.result_store = store
    return ws, p


def stored(ws) -> dict[str, dict]:
    with result.SQLiteReader(str(ws.results_dir / "results.db")) as reader:
        return {e.identifier: e.item for e in reader.read_all()}


def expected_records(exclude: tuple[str, ...] = ()) -> dict[str, dict]:
    out = {}
    for path in RECORD_FILES:
        if os.path.basename(path) in exclude:
            continue
        record = orjson.loads(_read(path))
        out[manager.cve_to_id(record["cveMetadata"]["cveId"])] = record
    return out


def test_records_written_unchanged(helpers, serve):
    serve(make_archive())
    ws, p = new_provider(helpers)
    p.update(None)

    # five records, nothing for README.md
    assert stored(ws) == expected_records()
    assert len(stored(ws)) == 5
    assert any(r["cveMetadata"]["state"] == "REJECTED" for r in stored(ws).values())
    for cve in ("2026/cve-2026-85091", "2026/cve-2026-59650", "2026/cve-2026-41608"):
        assert any(c["providerMetadata"]["shortName"] == "anchoreadp" for c in stored(ws)[cve]["containers"]["adp"])


def test_identifier_matches_nvd(helpers, serve):
    serve(make_archive())
    ws, p = new_provider(helpers)
    p.update(None)

    assert "2026/cve-2026-85091" in stored(ws)


def test_default_source():
    assert cve5.Config().url == "https://data.anchore.ninja/security/cve/enriched/json/v5/latest.json"


def test_default_source_requests(helpers, serve):
    serve(make_archive())
    ws = helpers.provider_workspace_helper(name=cve5.Provider.name())
    p = cve5.Provider(root=ws.root, config=cve5.Config())
    p.update(None)

    assert [url for url, _ in serve.calls] == [
        "https://data.anchore.ninja/security/cve/enriched/json/v5/latest.json",
        "https://data.anchore.ninja/security/cve/enriched/json/v5/" + ARCHIVE_PATH,
    ]


def test_user_agent_is_passed_through(helpers, serve):
    serve(make_archive())
    _, p = new_provider(helpers)
    p.update(None)

    assert [url for url, _ in serve.calls] == [MANIFEST_URL, ARCHIVE_URL]
    for _, kwargs in serve.calls:
        assert kwargs["user_agent"].startswith("anchore/vunnel-")


def test_source_from_environment_takes_precedence(helpers, serve, tmp_path, monkeypatch):
    yaml_url = "https://example.test/from-yaml/latest.json"
    env_url = "https://example.test/cve5/latest.json"
    cfg_file = tmp_path / ".vunnel.yaml"
    cfg_file.write_text(f"providers:\n  cve5:\n    url: {yaml_url}\n")

    assert config.load(str(cfg_file)).providers.cve5.url == yaml_url

    monkeypatch.setenv("VUNNEL_PROVIDERS_CVE5_URL", env_url)
    cfg = config.load(str(cfg_file))
    assert cfg.providers.cve5.url == env_url

    # another archive layout: records under cves/<year>/<bucket>xxx/
    serve(make_archive(layout=lambda name: f"cves/{name.split('-')[1]}/{name.split('-')[2][:2]}xxx/{name}"))
    ws = helpers.provider_workspace_helper(name=cve5.Provider.name())
    p = cve5.Provider(root=ws.root, config=cfg.providers.cve5)
    p.update(None)

    assert [url for url, _ in serve.calls] == [env_url, "https://example.test/cve5/" + ARCHIVE_PATH]
    assert stored(ws) == expected_records()


def test_each_run_replaces_results(helpers, serve):
    ws, p = new_provider(helpers)
    serve(make_archive())
    p.update(None)
    assert len(stored(ws)) == 5

    serve(make_archive(exclude=("CVE-2026-41608.json",)))
    p.update(None)
    assert stored(ws) == expected_records(exclude=("CVE-2026-41608.json",))
    assert len(stored(ws)) == 4


def _http_404(url):
    return requests.HTTPError(f"404 Client Error: Not Found for url: {url}")


def _cut(data: bytes) -> bytes:
    return data[:-1500]


FIRST = make_archive()
CUT = _cut(FIRST)
HALF_RECORD = _read(os.path.join(FIXTURES, "CVE-2026-85091.json"))
HALF_RECORD = HALF_RECORD[: len(HALF_RECORD) // 2]


@pytest.mark.parametrize(
    ("name", "setup", "match"),
    [
        ("manifest-404", {"errors": {MANIFEST_URL: _http_404}}, MANIFEST_URL),
        ("archive-404", {"errors": {ARCHIVE_URL: _http_404}}, ARCHIVE_URL),
        # checksum computed over the cut file, so the stream is what fails
        ("truncated", {"archive": CUT}, ARCHIVE_URL),
        ("checksum-mismatch", {"archive": FIRST, "manifest": {**manifest_for(FIRST), "checksum": PUBLISHED_CHECKSUM}}, ARCHIVE_URL),
        ("no-records", {"archive": make_archive(records=False)}, ARCHIVE_URL),
        # a deliberate edit of a real record: half of its bytes, so it is not valid JSON
        ("not-json", {"archive": make_archive(replace={"CVE-2026-85091.json": HALF_RECORD})}, "CVE-2026-85091.json"),
        ("manifest-not-object", {"manifest": b"[]"}, MANIFEST_URL),
        ("manifest-without-path", {"manifest": {"checksum": PUBLISHED_CHECKSUM}}, MANIFEST_URL),
        ("manifest-without-checksum", {"manifest": {"path": ARCHIVE_PATH}}, MANIFEST_URL),
        ("manifest-not-json", {"manifest": b"<html>"}, MANIFEST_URL),
    ],
)
def test_bad_source_fails_and_keeps_previous_results(helpers, serve, name, setup, match):  # noqa: ARG001
    ws, p = new_provider(helpers)
    serve(FIRST)
    p.update(None)
    before = stored(ws)
    assert len(before) == 5

    # serve() keeps the first run's archive and manifest unless the case replaces them
    serve(**setup)
    with pytest.raises(Exception, match=match) as exc:
        p.update(None)

    assert match in str(exc.value)
    assert stored(ws) == before


def test_schema_valid_and_snapshot(helpers, serve):
    serve(make_archive())
    ws = helpers.provider_workspace_helper(name=cve5.Provider.name(), snapshot_prefix="records")
    p = cve5.Provider(root=ws.root, config=cve5.Config(url=MANIFEST_URL))
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p.update(None)

    assert ws.num_result_entries() == 5
    assert ws.result_schemas_valid(require_entries=True)
    for f in ws.result_files():
        assert orjson.loads(_read(f))["schema"].endswith("schema/vulnerability/cve5/schema-5.2.0.json")
    ws.assert_result_snapshots()


def test_schema_invalid_record_is_written_unchanged(helpers, serve):
    serve(make_archive(include=(INVALID,)))
    ws, p = new_provider(helpers, store=result.StoreStrategy.FLAT_FILE)
    p.update(None)

    # the run succeeds and the record is stored as published, even though it fails the schema
    assert ws.num_result_entries() == 6
    items = [orjson.loads(_read(f))["item"] for f in ws.result_files()]
    assert orjson.loads(_read(os.path.join(FIXTURES, INVALID))) in items
    with pytest.raises(jsonschema.ValidationError):
        ws.result_schemas_valid()
