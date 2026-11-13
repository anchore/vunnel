from __future__ import annotations

import os
import shutil
from unittest.mock import patch

import pytest
from vunnel import result
from vunnel.providers.cpan import Config, Provider
from vunnel.providers.cpan.parser import (
    Parser,
    _main_module_alias,
    in_range,
    normalize_severity,
    perl_version_key,
    resolve_affected,
)


def vectors(section: str) -> list[list[str]]:
    """Rows of one section of the shared perl version vector table.

    The table is committed verbatim as fixture data and is the same table that drives grype's Go
    comparator, so the two implementations are held to identical pairs.
    """
    path = os.path.join(os.path.dirname(__file__), "test-fixtures", "perl-version-vectors.txt")
    rows = []
    current = None
    with open(path) as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("# "):
                current = line[2:].strip()
                continue
            if not line.strip() or line.startswith("#") or line.startswith("input "):
                continue
            if current == section:
                rows.append(line.replace("->", " -> ").split())
    assert rows, f"no vectors found for section {section!r}"
    return rows


@pytest.mark.parametrize("row", vectors("normalization"), ids=lambda row: row[0])
def test_perl_version_normalization(row):
    # the normal form is dotted-decimal, so it takes the other parse branch: agreeing with it is a
    # real check on the decimal three-digit-group chopping, not a tautology
    raw, _, normal = row[0], row[1], row[2]
    assert perl_version_key(raw) == perl_version_key(normal)


@pytest.mark.parametrize("row", vectors("ordering"), ids=lambda row: f"{row[0]}{row[3]}{row[2]}")
def test_perl_version_ordering(row):
    left, right, expected = perl_version_key(row[0]), perl_version_key(row[2]), row[4]
    got = "==" if left == right else (">" if left > right else "<")
    assert got == expected


@pytest.mark.parametrize("row", vectors("parse edges, lax mode"), ids=lambda row: row[0])
def test_perl_version_parse_edges(row):
    raw, expected = row[0].strip("'"), row[2]
    if expected == "FAIL":
        with pytest.raises(ValueError):
            perl_version_key(raw)
    else:
        assert perl_version_key(raw) == perl_version_key(expected)


def test_perl_version_undef_is_zero():
    """$LAX carries an `undef` alternative and version->parse("undef") yields 0.

    ExtUtils::MM->parse_version returns the literal string when it finds no $VERSION, so it can
    reach a consumer. Rejecting it was the only place this port disagreed with the Go
    implementation across the full shared vector table.
    """
    assert perl_version_key("undef") == perl_version_key("0")
    assert perl_version_key("undef") == perl_version_key("v0")
    assert perl_version_key("undef") < perl_version_key("0.001")


@pytest.mark.parametrize(
    "version,expr,expected",
    [
        # a bare version means >=, not ==, matching CPAN::Audit::Version::in_range. this is the
        # single most common range shape in CPANSA (616 of 1850 advisories)
        ("1.23", "1.23", True),
        ("1.24", "1.23", True),
        ("1.22", "1.23", False),
        # the single-equals form upstream's own regex does not match
        ("1.05", "=1.05", True),
        ("1.06", "=1.05", False),
        ("1.05", "==1.05", True),
        # comma separated clauses are ANDed
        ("1.20_01", ">=1.19_01,<=1.22_04", True),
        ("1.18", ">=1.19_01,<=1.22_04", False),
        ("9.30", "<9.31", True),
        ("9.31", "<9.31", False),
        ("9.31", ">=9.31", True),
        ("1.24", "!=1.23", True),
        # perl ordering, not lexical or semver: 4.09 really is below 4.10
        ("4.09", "<4.10", True),
        ("4.10", "<4.10", False),
        # perl's own release history is decimal while its advisories are dotted
        ("5.022001", ">=5.22.0,<5.24.0", True),
        ("5.024001", ">=5.22.0,<5.24.0", False),
    ],
)
def test_in_range(version, expr, expected):
    assert in_range(version, expr) is expected


@pytest.mark.parametrize("expr", ["", "  ", ">>1.2", "1.2 3.4"])
def test_in_range_reports_unparseable(expr):
    with pytest.raises(ValueError):
        in_range("1.2", expr)


def test_resolve_affected_subtracts_fixed():
    released = ["9.29", "9.30", "9.31", "9.32"]
    advisory = {"affected_versions": ["<9.31"], "fixed_versions": [">=9.31"]}
    assert resolve_affected(advisory, released) == ["9.29", "9.30"]


def test_resolve_affected_without_fixed_versions():
    # fixed_versions is absent on 73% of advisories; that means nothing is subtracted
    released = ["0.02", "0.03", "0.04"]
    assert resolve_affected({"affected_versions": ["0.03"]}, released) == ["0.03", "0.04"]


def test_resolve_affected_unions_disjoint_ranges():
    released = ["5.020003", "5.022001", "5.022002", "5.023001", "5.023007"]
    advisory = {"affected_versions": [">=5.005,<5.22.2", ">=5.23.0,<5.23.7"]}
    assert resolve_affected(advisory, released) == ["5.020003", "5.022001", "5.023001"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("moderate", "medium"),
        ("minor", "low"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("critical", "critical"),
        ("HIGH", "high"),
        (None, None),
        ("", None),
    ],
)
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


def stage(helpers, workspace):
    shutil.copytree(helpers.local_dir("test-fixtures"), workspace.input_dir, dirs_exist_ok=True)


def records(helpers, workspace):
    stage(helpers, workspace)
    parser = Parser(ws=workspace, logger=None)
    with patch.object(Parser, "_download", return_value=None):
        return dict(parser.get())


@pytest.fixture
def workspace(helpers):
    return helpers.provider_workspace_helper(name=Provider.name())


def test_record_identity(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    by_id = records(helpers, workspace)

    record = by_id["CPANSA-libwww-perl-2011-01"]
    assert record["id"] == "CPANSA-libwww-perl-2011-01"
    assert record["aliases"] == ["CVE-2011-0633"]
    assert record["affected"][0]["package"] == {"ecosystem": "CPAN", "name": "libwww-perl"}

    # distribution names are used verbatim, with no case normalization anywhere
    assert by_id["CPANSA-DBD-SQLite-2018-8740-sqlite"]["affected"][0]["package"]["name"] == "DBD-SQLite"


def test_upstream_generation_metadata_is_recorded(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    by_id = records(helpers, workspace)
    specific = by_id["CPANSA-libwww-perl-2011-01"]["database_specific"]
    assert specific["cpansa_commit"] == "2089ff7201b44e5e462742a5baaa080ba003d257"
    assert specific["cpansa_generated"] == "Sun Jul 26 06:23:50 2026"


def test_one_id_with_many_entries_yields_one_record(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    # CPANSA-DBD-SQLite-2018-8740-sqlite is 65 separate entries, each one slice of the affected
    # range, including the =N shape. they union into one record, not 65
    by_id = records(helpers, workspace)
    ranges = by_id["CPANSA-DBD-SQLite-2018-8740-sqlite"]["affected"][0]["ranges"]
    assert len(ranges) == 1
    assert ranges[0]["events"] == [
        {"introduced": "1.00"},
        {"fixed": "1.35"},
        {"introduced": "1.36_01"},
        {"fixed": "1.47_04"},
        {"introduced": "1.47_05"},
        {"fixed": "1.59_01"},
    ]


def test_decimal_release_history_resolves_against_dotted_ranges(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    # CPANSA records perl's releases in decimal form (5.022000) and writes its advisories in dotted
    # form (<5.24.0). only perl version rules resolve one against the other; a string comparison
    # resolves this advisory to nothing
    by_id = records(helpers, workspace)
    events = by_id["CPANSA-perl-2016-6185"]["affected"][0]["ranges"][0]["events"]
    assert events == [{"introduced": "5.022000"}, {"fixed": "5.024000"}]


def test_one_id_across_two_distributions_yields_one_record(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    # CPANSA-ExtUtils-ParseXS-2016-1238 is filed against both ExtUtils-ParseXS and perl. keying only
    # by distribution would emit two records with the same id and the second would overwrite the first
    by_id = records(helpers, workspace)
    affected = by_id["CPANSA-ExtUtils-ParseXS-2016-1238"]["affected"]
    assert [a["package"]["name"] for a in affected] == ["ExtUtils-ParseXS", "perl"]


@pytest.mark.parametrize(
    "dist_name,dist,expected",
    [
        # the case that motivates this: libwww-perl installs to auto/LWP/.packlist
        ("libwww-perl", {"main_module": "LWP"}, "LWP"),
        ("MIME-tools", {"main_module": "MIME::Body"}, "MIME-Body"),
        ("PathTools", {"main_module": "Cwd"}, "Cwd"),
        # the common case: the main module dashes back into the distribution name, so nothing is added
        ("JSON-MaybeXS", {"main_module": "JSON::MaybeXS"}, None),
        ("perl", {"main_module": "perl"}, None),
        # unusable main modules are left alone rather than guessed at from the distribution name
        ("urxvt-bgdsl", {"main_module": ""}, None),
        ("ActivePerl", {}, None),
        ("MT", {"main_module": None}, None),
    ],
)
def test_main_module_alias(dist_name, dist, expected):
    assert _main_module_alias(dist_name, dist) == expected


def test_main_module_alias_is_an_extra_affected_package(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    # libwww-perl's main module is LWP, so a packlist install of it is reported as `LWP` and matches
    # no advisory by distribution name. the alias rides along on the same advisory with identical
    # ranges rather than becoming a second record with the same id
    by_id = records(helpers, workspace)

    affected = by_id["CPANSA-libwww-perl-2011-01"]["affected"]
    assert [a["package"]["name"] for a in affected] == ["libwww-perl", "LWP"]
    assert affected[0]["ranges"] == affected[1]["ranges"]

    # round-tripping main modules add nothing, and neither does an empty one
    assert [a["package"]["name"] for a in by_id["CPANSA-CGI-Session-2006-01"]["affected"]] == ["CGI-Session"]
    assert [a["package"]["name"] for a in by_id["CPANSA-urxvt-bgdsl-2022-4170"]["affected"]] == ["urxvt-bgdsl"]


def test_severity_is_normalized_and_never_invented(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    by_id = records(helpers, workspace)
    assert by_id["CPANSA-perl-2015-8608"]["database_specific"]["severity"] == "critical"
    # a null severity emits no severity at all rather than a fabricated default
    assert "severity" not in by_id["CPANSA-Mojolicious-2022-03"]["database_specific"]
    # on 120 advisories the severity key is absent rather than null
    assert "severity" not in by_id["CPANSA-libwww-perl-2011-01"]["database_specific"]


def test_missing_generation_metadata_fails_loudly(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    stage(helpers, workspace)
    parser = Parser(ws=workspace, logger=None)
    with open(parser.file_path, "w") as f:
        f.write('{"meta": {}, "dists": {}}')

    with patch.object(Parser, "_download", return_value=None), pytest.raises(ValueError):
        list(parser.get())


def test_provider_schema(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    stage(helpers, workspace)

    with patch.object(Parser, "_download", return_value=None):
        p.update(None)

    assert workspace.num_result_entries() == 17
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, workspace, auto_fake_fixdate_finder, disable_get_requests):
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    stage(helpers, workspace)

    with patch.object(Parser, "_download", return_value=None):
        p.update(None)

    workspace.assert_result_snapshots()


def test_provider_skip_download(helpers, workspace, auto_fake_fixdate_finder, monkeypatch):
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)
    stage(helpers, workspace)

    def _fail_on_http(*args, **kwargs):
        raise RuntimeError("HTTP request attempted during skip_download test")

    monkeypatch.setattr("vunnel.utils.http_wrapper.get", _fail_on_http)

    p.update(None)

    assert workspace.num_result_entries() == 17
