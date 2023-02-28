# Developing

## Getting Started

This project requires:
- python (>= 3.7)
- pip (>= 22.2)
- poetry (>= 1.2): see [installation instructions](https://python-poetry.org/docs/#installation)

Once you have python and poetry installed, get the project bootstrapped:

```bash
# get basic project tooling
make bootstrap

# get a persistent virtual environment to work within
poetry shell

# install project dependencies
poetry install
```

[Pre-commit](https://pre-commit.com/) is used to help enforce static analysis checks with git hooks:

```bash
poetry run pre-commit install --hook-type pre-push
```

To jump into a poetry-managed virtualenv run `poetry shell`, this will prevent the need for `poetry run...` prefix for each command.

## Developing

If you want to use a locally-editable copy of vunnel while you develop:

```bash
poetry shell
pip uninstall vunnel  #... if you already have vunnel installed in this virtual env
pip install -e .
```

To run all static-analysis and tests:

```bash
make
```

Or run them individually:

```bash
make static-analysis
make test
```

If you want to see all of the things you can do:

```bash
make help
```


## What might need refactoring?

The best way is to look for [issues with the `refactor` label](https://github.com/anchore/vunnel/issues?q=is%3Aissue+is%3Aopen+label%3Arefactor).

More general ways would be to use `radon` to search for complexity and maintainability issues:

```
$ radon cc src --total-average -nb
src/vunnel/provider.py
    M 115:4 Provider._on_error - B
src/vunnel/providers/alpine/parser.py
    M 73:4 Parser._download - C
    M 178:4 Parser._normalize - C
    M 141:4 Parser._load - B
    C 44:0 Parser - B
src/vunnel/providers/amazon/parser.py
    M 66:4 Parser._parse_rss - C
    C 164:0 JsonifierMixin - C
    M 165:4 JsonifierMixin.json - C
    C 32:0 Parser - B
    M 239:4 PackagesHTMLParser.handle_data - B
...
```

The output of radon indicates the type (M=method, C=class, F=function), the path/name, and a A-F grade. Anything that's not an `A` is worth taking a look at.

Another approach is to use [`wily`](https://github.com/tonybaloney/wily):
```
$ wily build
...
$ wily rank
-----------Rank for Maintainability Index for bdb4983 by Alex Goodman on 2022-12-25.------------
╒═════════════════════════════════════════════════╤═════════════════════════╕
│ File                                            │   Maintainability Index │
╞═════════════════════════════════════════════════╪═════════════════════════╡
│ src/vunnel/providers/rhel/parser.py             │                 21.591  │
├─────────────────────────────────────────────────┼─────────────────────────┤
│ src/vunnel/providers/ubuntu/parser.py           │                 21.6144 │
├─────────────────────────────────────────────────┼─────────────────────────┤
│ tests/unit/providers/github/test_github.py      │                 35.3599 │
├─────────────────────────────────────────────────┼─────────────────────────┤
│ tests/unit/utils/test_oval_v2.py                │                 36.3388 │
├─────────────────────────────────────────────────┼─────────────────────────┤
│ src/vunnel/providers/debian/parser.py           │                 37.3723 │
├─────────────────────────────────────────────────┼─────────────────────────┤
│ tests/unit/utils/test_fdb.py                    │                 38.6926 │
├─────────────────────────────────────────────────┼─────────────────────────┤
│ tests/unit/providers/sles/test_sles.py          │                 41.6602 │
├─────────────────────────────────────────────────┼─────────────────────────┤
│ tests/unit/providers/ubuntu/test_ubuntu.py      │                 43.1323 │
├─────────────────────────────────────────────────┼─────────────────────────┤
...
```

Ideally we should try to get `wily diff` output into the CI pipeline and post on a sticky PR comment to show regressions (and potentially fail the CI run).

## Not everything has types...

This codebase has been ported from another repo that did not have any type hints. This is OK, though ideally over time this should
be corrected as new features are added and bug fixes made.

We use `mypy` today for static type checking, however, the ported code has been explicitly ignored (see `pyproject.toml`).

If you want to make enhancements in this area consider using automated tooling such as [`pytype`](https://github.com/google/pytype) to generate types via inference into `.pyi` files and later merge them into the codebase with [`merge-pyi`](https://github.com/google/pytype/tree/main/pytype/tools/merge_pyi).

Alternatively a tool like [`MonkeyType`](https://github.com/Instagram/MonkeyType) can be used generate static types from runtime data and incorporate into the code.

## Architecture

Vunnel is a CLI wrapper around multiple vulnerability data providers. All provider implementations should...
- live under `src/vunnel/providers` in their own directory (e.g. the NVD provider code is under `src/vunnel/providers/nvd/...`)
- have a class that implements the [`Provider` interface](https://github.com/anchore/vunnel/blob/1285a3be0f24fd6472c1f469dd327541ff1fc01e/src/vunnel/provider.py#L73)
- be centrally registered with a unique name under [`src/vunnel/providers/__init__.py`](https://github.com/anchore/vunnel/blob/1285a3be0f24fd6472c1f469dd327541ff1fc01e/src/vunnel/providers/__init__.py)
- be independent from other vulnerability providers data --that is, the debian provider CANNOT reach into the NVD data provider directory to look up information (such as severity)
- follow the workspace conventions for downloaded provider inputs, produced results, and tracking of metadata


Each provider is given a "workspace" directory within the vunnel `root` directory named after the provider.

```yaml
data/                       # the "vunnel root" directory
└── alpine/                 # the provider workspace directory
    ├── input/              # any file that needs to be downloaded and referenced should be stored here
    ├── results/            # schema-compliant vulnerability results (1 record per file)
    ├── checksums           # listing of result file checksums (xxh64 algorithm)
    └── metadata.json       # metadata about the input and result files
```

The `metadata.json` and `checksums` are written out after all results are written to `results/`. An example `metadata.json`:
```json
{
    "provider": "amazon",
    "urls": [
        "https://alas.aws.amazon.com/AL2022/alas.rss"
    ],
    "listing": {
        "digest": "dd3bb0f6c21f3936",
        "path": "checksums",
        "algorithm": "xxh64"
    },
    "timestamp": "2023-01-01T21:20:57.504194+00:00",
    "schema": {
        "version": "1.0.0",
        "url": "https://raw.githubusercontent.com/anchore/vunnel/main/schema/provider-workspace-state/schema-1.0.0.json"
    }
}
```
Where:
-  `provider`: the name of the provider that generated the results
- `urls`: the URLs that were referenced to generate the results
- `listing`: the path to the `checksums` listing file that lists all of the results, the checksum of that file, and the algorithm used to checksum the file (and the same algorithm used for all contained checksums)
- `timestamp`: the point in time when the results were generated or last updated
- `schema`: the data shape that the current file conforms to

All results stored in `results/**/*.json` should follow have `schema`, `identifier`, and `item` fields contained within an object.

- `schema`: the vulnerability schema which the `.item` field conforms to
- `identifier`: a string that uniquely identifies the current vulnerability record within the entire `results` directory
- `item`: the vulnerability record

For example:
```json
{
    "schema": "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
    "identifier": "3.3/cve-2015-8366",
    "item": {
        "Vulnerability": {
            "Severity": "Unknown",
            "NamespaceName": "alpine:3.3",
            "FixedIn": [
                {
                    "VersionFormat": "apk",
                    "NamespaceName": "alpine:3.3",
                    "Name": "libraw",
                    "Version": "0.17.1-r0"
                }
            ],
            "Link": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8366",
            "Description": "",
            "Metadata": {},
            "Name": "CVE-2015-8366",
            "CVSS": []
        }
    }
}
```

Note that the identifier is `3.3/cve-2015-8366` and not just `cve-2015-8366` in order to uniquely identify `cve-2015-8366` as applied to the `alpine 3.3` distro version among other records in the results directory.

Possible vulnerability schemas supported within the vunnel repo are:
- [GitHub Security Advisories](https://github.com/anchore/vunnel/tree/main/schema/vulnerability/github-security-advisory)
- [Generic OS Vulnerability](https://github.com/anchore/vunnel/tree/main/schema/vulnerability/os)
- [NVD Vulnerability](https://github.com/anchore/vunnel/tree/main/schema/vulnerability/nvd)
