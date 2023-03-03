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


## Adding a new provider

"Vulnerability matching" is the process of taking a list of vulnerabilities and matching them against a list of packages.
A provider in this repo is responsible for the "vulnerability" side of this process. The "package" side is handled by
[Syft](github.com/anchore/syft). A prerequisite for adding a new provider is that Syft can catalog the package types that
the provider is feeding vulnerability data for, so [Grype](github.com/anchore/grype) can perform the matching from these two sources.

To add a new provider, you will need to create a new provider class  under `/src/vunnel/providers/<name>` that inherits from `provider.Provider` and implements:
- `name()`: a unique and semantically-useful name for the provider (same as the name of the directory)
- `update()`: downloads and processes the raw data, writing all results with `self.results_writer()`

All results must conform to a [particular schema](https://github.com/anchore/vunnel/tree/main/schema), today there are a few kinds:
- `os`: a generic operating system vulnerability
- `nvd`: tailored to describe vulnerabilities from the NVD
- `github-security-advisory`: tailored to describe vulnerabilities from GitHub

Validating this provider has different implications depending on what is being added. For example, if the provider is
adding a new vulnerability source but is ultimately using an existing schema to express results then there is very little to do!
If you are adding a new schema, then the downstream data pipeline will need to be altered to support reading data in the new schema.

### ...for an existing schema

1. Fork Vunnel and add the new provider.

You should be able to see the new provider in the `vunnel list` command and run it with `vunnel run <name>`.
The entries written should write out to a specific `namespace` in the DB downstream, as indicated in the record.
This namespace is needed when making Grype changes.


2. Fork Grype and map distro type to a specific namespace.

This step might not be needed depending on the provider. Any change needed would be in the current grype db schema namespace index: https://github.com/anchore/grype/blob/main/grype/db/v5/namespace/index.go .


3. In Vunnel: add a new test case to `tests/quality/config.yaml` for the new provider.

The configuration maps a provider to test to specific images to test with, for example:
```yaml
...
  - provider: amazon
    images:
      - docker.io/amazonlinux:2@sha256:1301cc9f889f21dc45733df9e58034ac1c318202b4b0f0a08d88b3fdc03004de
      - docker.io/anchore/test_images:vulnerabilities-amazonlinux-2-5c26ce9@sha256:cf742eca189b02902a0a7926ac3fbb423e799937bf4358b0d2acc6cc36ab82aa
...
```

These images are used to test the provider on PRs and nightly builds to verify the specific provider is working.
Always use both the image tag and digest for all container image entries.
Pick an image that has a good representation of the package types that your new provider is adding vulnerability data for.


4. In Vunnel: swap the tools to your Grype branch in `tests/quality/config.yaml`.

If you wanted to see PR quality gate checks pass with your specific Grype changes (if you have any) then you can update the
`yardstick.tools[*]` entries for grype to use the a version that points to your fork (w.g. `your-fork-username/grype@main`).
If you don't have any grype changes needed then you can skip this step.


5. In Vunnel: add new "vulnerability match labels" to annotate True and False positive findings with Grype.

In order to evaluate the quality of the new provider, we need to know what the expected results are. This is done by
annotating Grype results with "True Positive" labels (good results) and "False Positive" labels (bad results). We'll use
[Yardstick](github.com/anchore/yardstick) to do this:

```bash
$ cd tests/quality

# capture results with the development version of grype (from your fork)
$ make capture provider=<your-provider-name>

# list your results
$ yardstick result list | grep grype

d415064e-2bf3-4a1d-bda6-9c3957f2f71a  docker.io/anc...  grype@v0.58.0             2023-03...
75d1fe75-0890-4d89-a497-b1050826d9f6  docker.io/anc...  grype[custom-db]@bdcefd2  2023-03...

# use the "grype[custom-db]" result UUID and explore the results and add labels to each entry
$ yardstick label explore 75d1fe75-0890-4d89-a497-b1050826d9f6

# You can use the yardstick TUI to label results:
# - use "T" to label a row as a True Positive
# - use "F" to label a row as a False Positive
# - Ctrl-Z to undo a label
# - Ctrl-S to save your labels
# - Ctrl-C to quit when you are done

```

Later we'll open a PR in the [vulnerability-match-labels repo](github.com/anchore/vulnerability-match-labels) to persist these labels.
For the meantime we can iterate locally with the labels we've added.


6. In Vunnel: run the quality gate.

```bash
cd tests/quality

# runs your specific provider to gather vulnerability data, builds a DB, and runs grype with the new DB
make capture provider=<your-provider-name>

# evaluate the quality gate
make validate
```

This uses the latest Grype-DB release to build a DB and the specified Grype version with a DB containing only data from the new provider.

You are looking for a passing run before continuing further.


7. Open a [vulnerability-match-labels repo](github.com/anchore/vulnerability-match-labels) PR to persist the new labels.

Vunnel uses the labels in the vulnerability-Match-Labels repo via a git submodule. We've already added labels locally
within this submodule in an earlier step. To persist these labels we need to push them to a fork and open a PR:

```
# fork the github.com/anchore/vulnerability-match-labels repo, but you do not need to clone it...

# from the Vunnel repo...
$ cd tests/quality/vulnerability-match-labels

$ git remote add fork git@github.com:your-fork-name/vulnerability-match-labels.git
$ git checkout -b 'add-labels-for-<your-provider-name>'
$ git status

# you should see changes from the labels/ directory for your provider that you added

$ git add .
$ git commit -m 'add labels for <your-provider-name>'
$ git push fork add-labels-for-<your-provider-name>
```

At this point you can open a PR against in the [vulnerability-match-labels repo](github.com/anchore/vulnerability-match-labels).

_Note: you will not be able to open a Vunnel PR that passes PR checks until the labels are merged into the vulnerability-match-labels repo._

Once the PR is merged in the vulnerability-match-labels repo you can update the submodule in Vunnel to point to the latest commit in the vulnerability-match-labels repo.

```bash
$ cd tests/quality

$ git submodule update --remote vulnerability-match-labels
```


8. In Vunnel: open a PR with your new provider.

The PR will also run all of the same quality gate checks that you ran locally.

If you have Grype changes, you should also create a PR for that as well. The Vunnel PR will not pass PR checks until the Grype PR is merged and the `test/quality/config.yaml` file is updated to point back to the `latest` Grype version.


### ...for a new schema

This is the same process as listed above with a few additional steps:

1. You will need to add the new schema to the Vunnel repo in the `schemas` directory.
2. Grype-DB will need to be updated to support the new schema in the `pkg/provider/unmarshal` and `pkg/process/v*` directories.
3. The Vunnel `tests/quality/config.yaml` file will need to be updated to use development `grype-db.version`, pointing to your fork.
4. The final Vunnel PR will not be able to be merged until the Grype-DB PR is merged and the `tests/quality/config.yaml` file is updated to point back to the `latest` Grype-DB version.


## Architecture

Vunnel is a CLI tool that downloads and processes vulnerability data from various sources (in the codebase, these are called "providers").
It is designed to be extensible and easy to add new providers. Additionally, the Vunnel CLI tool is optimized to run
a single provider at a time, not orchestrating multiple providers at once. [Grype-db](github.com/anchore/grype-db) is the
tool that collates output from multiple providers and produces a single database, and is ultimately responsible for
orchestrating multiple Vunnel calls to prepare the input data.

All providers work within a common root directory, by default `./data`. Within this directory, each provider has its own
"workspace" subdirectory. By convention no provider should read or write outside of its own workspace. This implies that
providers are independent of each other and can be run in parallel safely.

Within a provider's workspace, there are a few common subdirectories:
```
data                     # vunnel root directory
└── wolfi                # "wolfi" provider workspace
    ├── input            # contains all raw data downloaded by the provider
    └── results          # contains all processed data produced by the provider
```

All results from a provider are handled by a common base class helper (`provider.Provider.results_writer()`) and is driven
by the application configuration (e.g. JSON flat files or SQLite database). The data shape of the results are
self-describing via an envelope with a schema reference. For example:

```json
{
  "schema": "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
  "identifier": "wolfi:rolling/CVE-2007-2728",
  "item": {
    "Vulnerability": {
      "Severity": "Unknown",
      "NamespaceName": "wolfi:rolling",
      "FixedIn": [
        {
          "Name": "php",
          "Version": "0",
          "VersionFormat": "apk",
          "NamespaceName": "wolfi:rolling"
        }
      ],
      "Link": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2728",
      "Description": "The soap extension in PHP calls php_rand_r with an uninitialized seed variable, which has...",
      "Metadata": {},
      "Name": "CVE-2007-2728",
      "CVSS": []
    }
  }
}
```

Note:
- the `schema` field is a URL to the schema that describes the data shape of the `item` field
- the `identifier` field should have a unique identifier within the context of the provider results
- the `item` field is the actual vulnerability data, and the shape of this field is defined by the schema

Currently only JSON payloads are supported at this time.


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
