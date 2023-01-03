# Developing

## Getting Started

This project requires:
- python (>= 3.7)
- pip (>= 22.2)
- poetry (>= 1.2): see [installation instructions](https://python-poetry.org/docs/#installation)

Once you have python and poetry installed, get the project bootstrapped:

```
# get a persistent virtual environment to work within
poetry shell

# install project dependencies
poetry install
```

[Pre-commit](https://pre-commit.com/) is used to help enforce static analysis checks with git hooks:

```
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
