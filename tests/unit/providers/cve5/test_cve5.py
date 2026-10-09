import glob
import io
import os
import tarfile
import time
from unittest.mock import MagicMock

import orjson
import pytest
import requests

from vunnel import result, workspace
from vunnel.cli import config
from vunnel.providers import cve5
from vunnel.providers.cve5 import manager

FIXTURES = os.path.join(os.path.dirname(__file__), "test-fixtures")

RECORD_FILES = sorted(glob.glob(os.path.join(FIXTURES, "CVE-*.json")))
SOURCE_URL = "https://example.test/cve5.tar.gz"


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _path_in_cvelistv5(name: str) -> str:
    # CVE-2026-85091.json -> cvelistV5-main/cves/2026/85xxx/CVE-2026-85091.json
    year, num = name.removesuffix(".json").split("-")[1:]
    return f"cvelistV5-main/cves/{year}/{int(num) // 1000}xxx/{name}"


def make_tarball(
    exclude: tuple[str, ...] = (),
    layout=_path_in_cvelistv5,
    replace: dict[str, bytes] | None = None,
    records: bool = True,
) -> bytes:
    """pack the fixtures the way cvelistV5's archive does: records, plus files that are not records."""
    replace = replace or {}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        members = {"cvelistV5-main/README.md": b"# cvelistV5\n", "cvelistV5-main/cves/deltaLog.json": _read(os.path.join(FIXTURES, "deltaLog.json"))}
        if records:
            for path in RECORD_FILES:
                name = os.path.basename(path)
                if name in exclude:
                    continue
                members[layout(name)] = replace.get(name, _read(path))
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def serve(mocker):
    """patch the http layer so the provider downloads `payload` instead of using the network. returns the list of requested urls and kwargs."""
    calls = []
    state = {"payload": b"", "error": None}

    def fake_get(url, logger, **kwargs):
        calls.append((url, kwargs))
        if state["error"]:
            raise state["error"](url)
        response = MagicMock(status_code=200, iter_content=lambda chunk_size=None: [state["payload"]])  # noqa: ARG005
        response.__enter__.return_value = response
        return response

    mocker.patch("vunnel.utils.http_wrapper.get", side_effect=fake_get)
    mocker.patch.object(time, "sleep")

    def configure(payload: bytes | None = None, error=None):
        if payload is not None:
            state["payload"] = payload
        state["error"] = error
        return calls

    configure.calls = calls
    return configure


def new_provider(helpers, store=result.StoreStrategy.SQLITE, **cfg):
    ws = helpers.provider_workspace_helper(name=cve5.Provider.name())
    p = cve5.Provider(root=ws.root, config=cve5.Config(url=SOURCE_URL, **cfg))
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
    serve(make_tarball())
    ws, p = new_provider(helpers)
    p.update(None)

    # five records, nothing for README.md or deltaLog.json
    assert stored(ws) == expected_records()
    assert len(stored(ws)) == 5
    assert any(r["cveMetadata"]["state"] == "REJECTED" for r in stored(ws).values())


def test_identifier_matches_nvd(helpers, serve):
    serve(make_tarball())
    ws, p = new_provider(helpers)
    p.update(None)

    assert "2026/cve-2026-85091" in stored(ws)


def test_default_source():
    assert cve5.Config().url == "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.tar.gz"


def test_user_agent_is_passed_through(helpers, serve):
    serve(make_tarball())
    _, p = new_provider(helpers)
    p.update(None)

    url, kwargs = serve.calls[0]
    assert url == SOURCE_URL
    assert kwargs["user_agent"].startswith("anchore/vunnel-")


def test_source_from_environment_takes_precedence(helpers, serve, tmp_path, monkeypatch):
    yaml_url = "https://example.test/from-yaml.tar.gz"
    env_url = "https://example.test/from-env.tar.gz"
    cfg_file = tmp_path / ".vunnel.yaml"
    cfg_file.write_text(f"providers:\n  cve5:\n    url: {yaml_url}\n")

    assert config.load(str(cfg_file)).providers.cve5.url == yaml_url

    monkeypatch.setenv("VUNNEL_PROVIDERS_CVE5_URL", env_url)
    cfg = config.load(str(cfg_file))
    assert cfg.providers.cve5.url == env_url

    # another archive layout: records under data/<year>/<bucket>/
    serve(make_tarball(layout=lambda name: f"data/{name.split('-')[1]}/{name.split('-')[2][:2]}/{name}"))
    ws = helpers.provider_workspace_helper(name=cve5.Provider.name())
    p = cve5.Provider(root=ws.root, config=cfg.providers.cve5)
    p.update(None)

    assert serve.calls[0][0] == env_url
    assert stored(ws) == expected_records()


def test_each_run_replaces_results(helpers, serve):
    ws, p = new_provider(helpers)
    serve(make_tarball())
    p.update(None)
    assert len(stored(ws)) == 5

    serve(make_tarball(exclude=("CVE-2026-41608.json",)))
    p.update(None)
    assert stored(ws) == expected_records(exclude=("CVE-2026-41608.json",))
    assert len(stored(ws)) == 4


def _http_404(url):
    return requests.HTTPError(f"404 Client Error: Not Found for url: {url}")


@pytest.mark.parametrize(
    ("name", "setup", "match"),
    [
        ("404", {"error": _http_404}, SOURCE_URL),
        ("truncated", {"payload": make_tarball()[:-1500]}, SOURCE_URL),
        ("no-records", {"payload": make_tarball(records=False)}, SOURCE_URL),
        # a deliberate edit of a real record: half of its bytes, so it is not valid JSON
        (
            "not-json",
            {"payload": make_tarball(replace={"CVE-2026-85091.json": _read(os.path.join(FIXTURES, "CVE-2026-85091.json"))[:3700]})},
            "CVE-2026-85091.json",
        ),
    ],
)
def test_bad_source_fails_and_keeps_previous_results(helpers, serve, name, setup, match):  # noqa: ARG001
    ws, p = new_provider(helpers)
    serve(make_tarball())
    p.update(None)
    before = stored(ws)
    assert len(before) == 5

    serve(**setup)
    with pytest.raises(Exception, match=match) as exc:
        p.update(None)

    assert SOURCE_URL in str(exc.value)
    assert stored(ws) == before


def test_schema_valid_and_snapshot(helpers, serve):
    serve(make_tarball())
    ws = helpers.provider_workspace_helper(name=cve5.Provider.name(), snapshot_prefix="records")
    p = cve5.Provider(root=ws.root, config=cve5.Config(url=SOURCE_URL))
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p.update(None)

    assert ws.num_result_entries() == 5
    assert ws.result_schemas_valid(require_entries=True)
    for f in ws.result_files():
        assert orjson.loads(_read(f))["schema"].endswith("schema/vulnerability/cve5/schema-5.2.0.json")
    ws.assert_result_snapshots()
