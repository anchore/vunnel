from __future__ import annotations

import http.server
import importlib.util
import os
import pathlib
import subprocess
import threading
from types import SimpleNamespace

import pytest
import requests

SCRIPT = pathlib.Path(__file__).resolve().parents[4] / "scripts" / "generate-go-release-dates.py"


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location("generate_go_release_dates", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.urls = []

    def get(self, url, timeout, allow_redirects=True):
        assert allow_redirects is False, "the generator must not follow redirects"
        self.urls.append(url)
        result = self.handler(url)
        if isinstance(result, Exception):
            raise result
        return result


def ok(time):
    return SimpleNamespace(status_code=200, content=b'{"Time":"' + time.encode() + b'"}')


def status(code):
    return SimpleNamespace(status_code=code, content=b"")


def records(*pairs):
    return [
        {"affected": [{"package": {"name": m}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": v}]}]}]}
        for m, v in pairs
    ]


def test_new_versions_are_dated_or_recorded_unknown(generator):
    def handler(url):
        return ok("2023-08-01T17:46:51Z") if url == generator.module_info_url("golang.org/x/image", "0.10.0") else status(404)

    session = FakeSession(handler)

    table = generator.build_module_table(records(("golang.org/x/image", "0.10.0"), ("example.com/gone", "1.0.0")), {}, session)

    assert table == {"golang.org/x/image@0.10.0": "2023-08-01", "example.com/gone@1.0.0": None}


def test_committed_dates_are_final(generator):
    session = FakeSession(lambda url: pytest.fail(f"asked about {url}"))

    table = generator.build_module_table(records(("golang.org/x/image", "0.10.0")), {"golang.org/x/image@0.10.0": "2023-08-01"}, session)

    assert table == {"golang.org/x/image@0.10.0": "2023-08-01"}


def test_committed_unknowns_are_asked_again(generator):
    session = FakeSession(lambda url: ok("2026-09-01T00:00:00Z"))

    table = generator.build_module_table(records(("example.com/late", "1.0.0")), {"example.com/late@1.0.0": None}, session)

    assert table == {"example.com/late@1.0.0": "2026-09-01"}


FAILURES = pytest.mark.parametrize(
    "failure",
    [
        requests.exceptions.ConnectionError("connection refused"),
        status(500),
        status(429),
        # a 200 with a garbage time isn't an answer either, and must never be committed
        ok("0001-01-01T00:00:00+05:00"),
    ],
    ids=["refused", "server-error", "rate-limited", "garbage-date"],
)


@FAILURES
def test_a_straggler_never_rewrites_the_table(generator, failure):
    """Some lookups fail: a committed entry that couldn't be re-asked keeps its value, a new version
    that couldn't be asked is left for next time, and everything that was answered still lands."""

    def handler(url):
        return ok("2026-09-01T00:00:00Z") if url == generator.module_info_url("example.com/answered", "1.0.0") else failure

    table = generator.build_module_table(
        records(("example.com/known", "1.0.0"), ("example.com/new", "1.0.0"), ("example.com/answered", "1.0.0")),
        {"example.com/known@1.0.0": None},
        FakeSession(handler),
    )

    assert table == {"example.com/known@1.0.0": None, "example.com/answered@1.0.0": "2026-09-01"}


@FAILURES
def test_an_outage_is_an_error(generator, failure):
    """Every attempted lookup failed: the job did nothing useful, so it must fail rather than succeed quietly."""
    with pytest.raises(generator.Outage):
        generator.build_module_table(
            records(("example.com/known", "1.0.0"), ("example.com/new", "1.0.0")),
            {"example.com/known@1.0.0": None},
            FakeSession(lambda url: failure),
        )


def test_unaskable_module_paths_are_not_an_outage(generator):
    """A path we won't build a URL for is never asked, so it can't count as a failed lookup --
    otherwise one such fix version in the vulndb would fail every run."""
    session = FakeSession(lambda url: pytest.fail(f"asked about {url}"))

    assert generator.build_module_table(records(("../../evil", "1.0.0")), {}, session) == {}


def test_main_writes_nothing_and_fails_on_an_outage(generator, monkeypatch, tmp_path):
    stdlib_out, module_out = tmp_path / "stdlib.py", tmp_path / "modules.py"
    monkeypatch.setattr(generator, "OUTPUT_PATH", stdlib_out)
    monkeypatch.setattr(generator, "MODULE_OUTPUT_PATH", module_out)
    monkeypatch.setattr(generator, "build_stdlib_table", lambda: {"go1.21.5": "2023-12-05"})
    monkeypatch.setattr(generator, "download_vulndb_records", lambda: records(("example.com/new", "1.0.0")))
    monkeypatch.setattr(generator, "proxy_session", lambda: FakeSession(lambda url: requests.exceptions.ConnectionError("down")))
    monkeypatch.setattr("sys.argv", ["generate-go-release-dates.py"])

    assert generator.main() == 1
    assert not stdlib_out.exists()
    assert not module_out.exists()


def test_main_writes_what_it_learned_despite_stragglers(generator, monkeypatch, tmp_path):
    stdlib_out, module_out = tmp_path / "stdlib.py", tmp_path / "modules.py"
    monkeypatch.setattr(generator, "OUTPUT_PATH", stdlib_out)
    monkeypatch.setattr(generator, "MODULE_OUTPUT_PATH", module_out)
    monkeypatch.setattr(generator, "GO_MODULE_RELEASE_DATES", {})
    monkeypatch.setattr(generator, "build_stdlib_table", lambda: {"go1.21.5": "2023-12-05"})
    monkeypatch.setattr(generator, "download_vulndb_records", lambda: records(("a.io/m", "1.0.0"), ("b.io/m", "1.0.0")))
    monkeypatch.setattr(
        generator,
        "proxy_session",
        lambda: FakeSession(lambda url: ok("2026-09-01T00:00:00Z") if url == generator.module_info_url("a.io/m", "1.0.0") else status(503)),
    )
    monkeypatch.setattr("sys.argv", ["generate-go-release-dates.py"])

    assert generator.main() == 0
    assert '"a.io/m@1.0.0": "2026-09-01"' in module_out.read_text()
    assert "b.io/m" not in module_out.read_text()


def test_generator_retries_cap_retry_after(generator):
    """urllib3 would otherwise wait as long as Retry-After says -- hours, across 16 workers."""
    long_wait = SimpleNamespace(headers={"Retry-After": "21600"})
    retry = generator.PROXY_RETRIES

    assert retry.get_retry_after(long_wait) == generator.MAX_RETRY_AFTER_SECONDS == 60
    # and the cap survives the copies urllib3 makes on every retry
    assert retry.increment(method="GET", url="/x", response=None, error=None).get_retry_after(long_wait) == 60


def test_generator_backoff_is_jittered(generator):
    """16 workers backing off together must not all come back at the same instant."""
    assert generator.PROXY_RETRIES.backoff_jitter > 0


@pytest.fixture
def redirecting_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/start"):
                self.send_response(302)
                # same address the server is bound to, so a wrongly followed redirect really lands
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/landed")
                self.end_headers()
                return
            body = b'{"Time":"2020-01-02T00:00:00Z"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/start"
    server.shutdown()
    server.server_close()


def test_generator_does_not_follow_a_redirect_into_the_committed_table(generator, monkeypatch, redirecting_server):
    """Through a real session and server: whatever a redirect points at must never be committed."""
    monkeypatch.setattr(generator, "module_info_url", lambda module, version: redirecting_server)

    resolved = generator.resolve_modules([("example.com/m", "1.0.0")], generator.proxy_session(), workers=1)

    assert resolved.dates == {}
    assert resolved.failed == {"example.com/m@1.0.0"}


def test_versions_the_vulndb_no_longer_names_are_dropped(generator):
    session = FakeSession(lambda url: pytest.fail(f"asked about {url}"))

    table = generator.build_module_table(records(("golang.org/x/image", "0.10.0")), {"golang.org/x/image@0.10.0": "2023-08-01", "example.com/withdrawn@1.0.0": "2020-01-01"}, session)

    assert table == {"golang.org/x/image@0.10.0": "2023-08-01"}


def test_stdlib_is_not_in_the_module_table(generator):
    session = FakeSession(lambda url: pytest.fail(f"asked about {url}"))

    assert generator.build_module_table(records(("stdlib", "1.21.5"), ("toolchain", "1.21.5")), {}, session) == {}


def test_render_modules_round_trips(generator):
    table = {"b.io/m@1.0.0": None, "a.io/m@1.0.0": "2023-08-01"}

    rendered = generator.render_modules(table)
    namespace: dict = {}
    exec(compile(rendered, "<rendered>", "exec"), namespace)  # noqa: S102

    assert namespace["GO_MODULE_RELEASE_DATES"] == table
    # sorted, so regenerating is byte-stable
    assert rendered.index("a.io/m") < rendered.index("b.io/m")


# ---------------------------------------------------------------------------
# the stdlib half, against a real (local) git repository
# ---------------------------------------------------------------------------


@pytest.fixture
def tagged_repo(tmp_path):
    """A git repo whose tags are named and dated like golang/go's, plus some that must be dropped."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }

    def git(*args, date=None):
        run_env = {**env, **({"GIT_COMMITTER_DATE": date, "GIT_AUTHOR_DATE": date} if date else {})}
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args], cwd=tmp_path, env=run_env, check=True, capture_output=True)

    git("init", "-q")

    def commit_and_tag(tag, date, annotated_on=None):
        git("commit", "-q", "--allow-empty", "-m", tag, date=date)
        if annotated_on:
            git("tag", "-a", tag, "-m", tag, date=annotated_on)
        else:
            git("tag", tag)

    # late evening in -0800 is the next day in UTC
    commit_and_tag("go1.21.0", "2023-08-07T23:30:00-0800")
    # just after midnight UTC is the previous day anywhere in the Americas, so this one
    # catches the listing rendering dates in any timezone but UTC
    commit_and_tag("go1.21.1", "2023-09-06T01:00:00+0000")
    # annotated tag made long after the commit: the commit's date is the release date
    commit_and_tag("go1.22rc2", "2024-01-23T12:00:00+0000", annotated_on="2024-06-01T12:00:00+0000")
    # not release tags
    commit_and_tag("go1.4-bootstrap-20171003", "2017-10-03T12:00:00+0000")
    commit_and_tag("weekly.2011-01-01", "2011-01-01T12:00:00+0000")
    return SimpleNamespace(path=tmp_path, commit_and_tag=commit_and_tag)


def test_collect_release_dates_uses_utc_commit_dates_of_release_tags_only(generator, tagged_repo):
    """Against a real (local) git repo: UTC commit dates, annotated tags dated by their commit,
    and only tags the provider's own grammar can look up."""
    assert generator.collect_release_dates(str(tagged_repo.path)) == {
        "go1.21.0": "2023-08-08",
        "go1.21.1": "2023-09-06",
        "go1.22rc2": "2024-01-23",
    }


@pytest.mark.parametrize("date", ["2099-01-01T12:00:00+0000", "2001-01-01T12:00:00+0000"], ids=["future", "before-go"])
def test_collect_release_dates_rejects_out_of_range_dates_like_the_runtime_does(generator, tagged_repo, date):
    """A forged or rewritten mirror tag must not be committed as an accurate release date."""
    tagged_repo.commit_and_tag("go1.99.0", date)

    assert "go1.99.0" not in generator.collect_release_dates(str(tagged_repo.path))
