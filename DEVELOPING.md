# Developing

## Getting Started

This project requires:
- python (>= 3.7)
- pip (>= 22.2)
- uv
- docker
- go (>= 1.20)
- posix shell (bash, zsh, etc... needed for the `make dev` "development shell")

Once you have python and uv installed, get the project bootstrapped:

```bash
# clone grype and grype-db, which is needed for provider development
git clone git@github.com:anchore/grype.git
git clone git@github.com:anchore/grype-db.git
# note: if you already have these repos cloned, you can skip this step. However, if they
# reside in a different directory than where the vunnel repo is, then you will need to
# set the `GRYPE_PATH` and/or `GRYPE_DB_PATH` environment variables for the development
# shell to function. You can add these to a local .env file in the vunnel repo root.

# clone the vunnel repo
git clone git@github.com:anchore/vunnel.git
cd vunnel

# get basic project tooling
make bootstrap

# install project dependencies
uv sync --all-extras --dev
```

[Pre-commit](https://pre-commit.com/) is used to help enforce static analysis checks with git hooks:

```bash
uv run pre-commit install --hook-type pre-push
```

## Developing

The easiest way to develop on a providers is to use the development shell, selecting the specific provider(s) you'd like to focus your development workflow on:

```bash
# Specify one or more providers you want to develop on.
# Any provider from the output of "vunnel list" is valid.
# Specify multiple as a space-delimited list:
# make dev providers="oracle wolfi nvd"
$ make dev provider="oracle"

Entering vunnel development shell...
• Configuring with providers: oracle ...
• Writing grype config: /Users/wagoodman/code/vunnel/.grype.yaml ...
• Writing grype-db config: /Users/wagoodman/code/vunnel/.grype-db.yaml ...
• Activating virtual env: /Users/wagoodman/code/vunnel/.venv ...
• Installing editable version of vunnel ...
• Building grype ...
• Building grype-db ...

Note: development builds grype and grype-db are now available in your path.
To update these builds run 'make build-grype' and 'make build-grype-db' respectively.
To run your provider and update the grype database run 'make update-db'.
Type 'exit' to exit the development shell.
```

You can now run the provider you specified in the `make dev` command, build an isolated grype DB, and import the DB into grype:

```bash
$ make update-db
• Updating vunnel providers ...
[0000]  INFO grype-db version: ede464c2def9c085325e18ed319b36424d71180d-adhoc-build
...
[0000]  INFO configured providers parallelism=1 providers=1
[0000] DEBUG   └── oracle
[0000] DEBUG all providers started, waiting for graceful completion...
[0000]  INFO running vulnerability provider provider=oracle
[0000] DEBUG oracle:  2023-03-07 15:44:13 [INFO] running oracle provider
[0000] DEBUG oracle:  2023-03-07 15:44:13 [INFO] downloading ELSA from https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2
[0019] DEBUG oracle:  2023-03-07 15:44:31 [INFO] wrote 6298 entries
[0019] DEBUG oracle:  2023-03-07 15:44:31 [INFO] recording workspace state
• Building grype-db ...
[0000]  INFO grype-db version: ede464c2def9c085325e18ed319b36424d71180d-adhoc-build
[0000]  INFO reading all provider state
[0000]  INFO building DB build-directory=./build providers=[oracle] schema=5
• Packaging grype-db ...
[0000]  INFO grype-db version: ede464c2def9c085325e18ed319b36424d71180d-adhoc-build
[0000]  INFO packaging DB from="./build" for="https://toolbox-data.anchore.io/grype/databases"
[0000]  INFO created DB archive path=build/vulnerability-db_v5_2023-03-07T20:44:13Z_405ae93d52ac4cde6606.tar.gz
• Importing DB into grype ...
Vulnerability database imported
```

You can now run grype that uses the newly created DB:

```bash
$ grype oraclelinux:8.4
 ✔ Pulled image
 ✔ Loaded image
 ✔ Parsed image
 ✔ Cataloged packages      [195 packages]
 ✔ Scanning image...       [193 vulnerabilities]
   ├── 0 critical, 25 high, 146 medium, 22 low, 0 negligible
   └── 193 fixed

NAME                        INSTALLED                FIXED-IN                    TYPE  VULNERABILITY   SEVERITY
bind-export-libs            32:9.11.26-4.el8_4       32:9.11.26-6.el8            rpm   ELSA-2021-4384  Medium
bind-export-libs            32:9.11.26-4.el8_4       32:9.11.36-3.el8            rpm   ELSA-2022-2092  Medium
bind-export-libs            32:9.11.26-4.el8_4       32:9.11.36-3.el8_6.1        rpm   ELSA-2022-6778  High
bind-export-libs            32:9.11.26-4.el8_4       32:9.11.36-5.el8            rpm   ELSA-2022-7790  Medium

# note that we're using the database we just built...
$ grype db status
Location:  /Users/wagoodman/code/vunnel/.cache/grype/5  # <--- this is the local DB we just built
...

# also note that we're using a development build of grype
$ which grype
/Users/wagoodman/code/vunnel/bin/grype
```

The development builds of grype and grype-db provided are derived from `../grype` and `../grype-db` paths relative to the vunnel project.
If you want to use a different path, you can set the `GRYPE_PATH` and `GRYPE_DB_PATH` environment variables. This can be
persisted by adding a `.env` file to the root of the vunnel project:

```bash
# example .env file in the root of the vunnel repo
GRYPE_PATH=~/somewhere/else/grype
GRYPE_DB_PATH=~/also/somewhere/else/grype-db
```

To rebuild the grype and grype-db binaries from local source, run:

```bash
make build-grype
make build-grype-db
```

This project uses Make for running common development tasks:

```bash

make                  # run static analysis and unit testing
make static-analysis  # run static analysis
make unit             # run unit tests
make format           # format the codebase with black
make lint-fix         # attempt to automatically fix linting errors
...
```

If you want to see all of the things you can do:

```bash
make help
```

If you want to use a locally-editable copy of vunnel while you develop without the custom development shell:

```bash
uv pip uninstall vunnel  #... if you already have vunnel installed in this virtual env
uv pip install -e .
```

### Snapshot Tests

In order to ensure that the same feed state from providers would make the same
set of vulnerabilities, snapshot testing is used.

Snapshot tests are run as part of ordinary unit tests, and will run during
`make unit`.

To update snapshots, run the following pytest command. (Note that this example
is for the debian provider, and the test name and path will be different for
other providers):

``` sh
pytest ./tests/unit/providers/debian/test_debian.py -k test_provider_via_snapshot --snapshot-update
```

## Architecture

Vunnel is a CLI tool that downloads and processes vulnerability data from various sources (in the codebase, these are called "providers").

<!-- repo path: docs/vunnel-run-workflow.drawio -->
<!-- asset comment: https://github.com/anchore/vunnel/issues/102#issuecomment-1456403838 -->
<img src="https://user-images.githubusercontent.com/590471/223163266-e73d2595-f320-4607-a016-f1b22aad45c7.svg" width="600" />

Conceptually, one or more invocations of Vunnel will produce a single data directory which Grype-DB uses to create a Grype database:

<!-- repo path: docs/vunnel+grype-db-workflow.drawio -->
<!-- asset comment: https://github.com/anchore/vunnel/issues/102#issuecomment-1456408327 -->
<img src="https://user-images.githubusercontent.com/590471/223167464-aca39d4b-699a-47da-b852-fea904ba9824.svg" width="600" />

Additionally, the Vunnel CLI tool is optimized to run
a single provider at a time, not orchestrating multiple providers at once. [Grype-db](github.com/anchore/grype-db) is the
tool that collates output from multiple providers and produces a single database, and is ultimately responsible for
orchestrating multiple Vunnel calls to prepare the input data:

<!-- repo path: docs/grype-db-actions.drawio -->
<!-- asset comment: https://github.com/anchore/vunnel/issues/102#issuecomment-1456415533 -->
<img src="https://user-images.githubusercontent.com/590471/223165191-8b06b696-f7b5-4a92-912a-c7110c1cd324.svg" width="600" />

For more information about how Grype-DB uses Vunnel see [the Grype-DB documentation](https://github.com/anchore/grype-db/blob/main/DEVELOPING.md#architecture).


### Vunnel Providers

A "Provider" is the core abstraction for Vunnel and represents a single source of vulnerability data. Vunnel is a CLI wrapper
around multiple vulnerability data providers.

All provider implementations should...
- live under `src/vunnel/providers` in their own directory (e.g. the NVD provider code is under `src/vunnel/providers/nvd/...`)
- have a class that implements the [`Provider` interface](https://github.com/anchore/vunnel/blob/1285a3be0f24fd6472c1f469dd327541ff1fc01e/src/vunnel/provider.py#L73)
- be centrally registered with a unique name under [`src/vunnel/providers/__init__.py`](https://github.com/anchore/vunnel/blob/1285a3be0f24fd6472c1f469dd327541ff1fc01e/src/vunnel/providers/__init__.py)
- be independent from other vulnerability providers data --that is, the debian provider CANNOT reach into the NVD data provider directory to look up information (such as severity)
- follow the workspace conventions for downloaded provider inputs, produced results, and tracking of metadata

Each provider has a "workspace" directory within the "vunnel root" directory (defaults to `./data`) named after the provider.

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
- `provider`: the name of the provider that generated the results
- `urls`: the URLs that were referenced to generate the results
- `listing`: the path to the `checksums` listing file that lists all of the results, the checksum of that file, and the algorithm used to checksum the file (and the same algorithm used for all contained checksums)
- `timestamp`: the point in time when the results were generated or last updated
- `schema`: the data shape that the current file conforms to

All results from a provider are handled by a common base class helper (`provider.Provider.results_writer()`) and is driven
by the application configuration (e.g. JSON flat files or SQLite database). The data shape of the results are
self-describing via an envelope with a schema reference. For example:

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

Where:
- the `schema` field is a URL to the schema that describes the data shape of the `item` field
- the `identifier` field should have a unique identifier within the context of the provider results
- the `item` field is the actual vulnerability data, and the shape of this field is defined by the schema

Note that the identifier is `3.3/cve-2015-8366` and not just `cve-2015-8366` in order to uniquely identify
`cve-2015-8366` as applied to the `alpine 3.3` distro version among other records in the results directory.

Currently only JSON payloads are supported at this time.

Possible vulnerability schemas supported within the vunnel repo are:
- [Generic OS Vulnerability](https://github.com/anchore/vunnel/tree/main/schema/vulnerability/os)
- [GitHub Security Advisories](https://github.com/anchore/vunnel/tree/main/schema/vulnerability/github-security-advisory)
- [NVD Vulnerability](https://github.com/anchore/vunnel/tree/main/schema/vulnerability/nvd)
- [Open Source Vulnerability (OSV)](https://ossf.github.io/osv-schema)

If at any point a breaking change needs to be made to a provider (and say the schema remains the same), then you
can set the `__version__` attribute on the provider class to a new integer value (incrementing from `1` onwards). This
is a way to indicate that the cached input/results are not compatible with the output of the current version of the
provider, in which case the next invocation of the provider will delete the previous input and results before running.


### Provider configurations

Each provider has a configuration object defined next to the provider class. This object is used in the vunnel application
configuration and is passed as input to the provider class. Take the debian provider configuration for example:

```python
from dataclasses import dataclass, field

from vunnel import provider, result

@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125

```

Every provider configuration must:
- be a `dataclass`
- have a `runtime` field that is a `provider.RuntimeConfig` field

The `runtime` field is used to configure common behaviors of the provider that are enforced within the `vunnel.provider.Provider` subclass. Options include:

- `on_error`: what to do when the provider fails, sub fields include:
  - `action`: choose to `fail`, `skip`, or `retry` when the failure occurs
  - `retry_count`: the number of times to retry the provider before failing (only applicable when `action` is `retry`)
  - `retry_delay`: the number of seconds to wait between retries (only applicable when `action` is `retry`)
  - `input`: what to do about the `input` data directory on failure (such as `keep` or `delete`)
  - `results`: what to do about the `results` data directory on failure (such as `keep` or `delete`)

- `existing_results`: what to do when the provider is run again and the results directory already exists. Options include:
  - `delete-before-write`: delete the existing results just before writing the first processed (new) result
  - `delete`: delete existing results before running the provider
  - `keep`: keep the existing results

- `existing_input`: what to do when the provider is run again and the input directory already exists. Options include:
  - `delete`: delete the existing input before running the provider
  - `keep`: keep the existing input

- `result_store`: where to store the results. Options include:
  - `sqlite`: store results as key-value form in a SQLite database, where keys are the record identifiers values are the json vulnerability records
  - `flat-file`: store results in JSON files named after the record identifiers

Any provider-specific config options can be added to the configuration object as needed (such as `request_timeout`, which is a common field).


## Adding a new provider

"Vulnerability matching" is the process of taking a list of vulnerabilities and matching them against a list of packages.
A provider in this repo is responsible for the "vulnerability" side of this process. The "package" side is handled by
[Syft](github.com/anchore/syft). A prerequisite for adding a new provider is that Syft can catalog the package types that
the provider is feeding vulnerability data for, so [Grype](github.com/anchore/grype) can perform the matching from these two sources.

To add a new provider, you will need to create a new provider class  under `/src/vunnel/providers/<name>` that inherits from `provider.Provider` and implements:
- `name()`: a unique and semantically-useful name for the provider (same as the name of the directory)
- `update()`: downloads and processes the raw data, writing all results with `self.results_writer()`

All results must conform to a [particular schema](https://github.com/anchore/vunnel/tree/main/schema), today there are a few kinds:
- `os`: a generic operating system vulnerability (e.g redhat, debian, ubuntu, alpine, wolfi, minimos, etc.)
- `nvd`: tailored to describe vulnerabilities from the NVD
- `github-security-advisory`: tailored to describe vulnerabilities from GitHub
- `osv`: tailored to describe vulnerabilities from the [aggregated OSV vulnerability database](https://osv.dev/list)

Once the provider is implemented, you will need to wire it up into the application in a couple places:
- add a new entry under the dispatch table in `src/vunnel/providers/__init__.py` mapping your provider name to the class
- add the provider configuration to the application configuration under `src/vunnel/cli/config.py` (specifically the `Providers` dataclass)

For a more detailed example on the implementation details of a provider see the ["example" provider](example/README.md).

Validating this provider has different implications depending on what is being added. For example, if the provider is
adding a new vulnerability source but is ultimately using an existing schema to express results then there may be very little to do!
If you are adding a new schema, then the downstream data pipeline will need to be altered to support reading data in the new schema.

**_Please feel free to reach out to a maintainer on an incomplete draft PR and we can help you get it over the finish line!_**


### ...for an existing schema

#### **1. Fork Vunnel and add the new provider.**

Take a look at the example provider in the `example` directory. You are encouraged to copy `example/awesome/*` into
`src/vunnel/providers/YOURPROVIDERNAME/` and modify it to fit the needs of your new provider, however, this is not required:

```bash
# from the root of the vunnel repo
cp -a example/awesome src/vunnel/providers/YOURPROVIDERNAME

```

See the ["example" provider README](example/README.md) as well as the code comments for steps and considerations to take when implementing a new provider.

Once implemented, you should be able to see the new provider in the `vunnel list` command and run it with `vunnel run <name>`.
The entries written should write out to a specific `namespace` in the DB downstream, as indicated in the record.
This namespace is needed when making Grype changes.

While developing the provider consider using the `make dev provider="<your-provider-name>"`developer shell to run the provider and manually test the results against grype.

_**At this point you can optionally open a Vunnel PR with your new provider and a Maintainer can help with the next steps.**_ Or if you'd like to get PR changes merged faster you can continue with the next steps.


#### **2. Fork Grype and map distro type to a specific namespace.**

This step might not be needed depending on the provider.

Common reasons for needing Grype changes include:
- Grype does not support the distro type and it needs to be added. See the [grype/distro/types.go](https://github.com/anchore/grype/blob/main/grype/distro/type.go) file to add the new distro.
- Grype supports the distro already, but matching is disabled. See the [grype/distro/distro.go](https://github.com/anchore/grype/blob/main/grype/distro/distro.go) file to enable the distro explicitly.
- There is a non-standard mapping of distro to namespaces (e.g. redhat and centos map to `rhel`). See the grype db schema namespace index for possible changes: https://github.com/anchore/grype/blob/main/grype/db/v5/namespace/index.go .

If you're using the developer shell (`make dev ...`) then you can run `make build-grype` to get a build of grype with your changes.


#### **3. In Vunnel: add a new test case to `tests/quality/config.yaml` for the new provider.**

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


#### **4. In Vunnel: swap the tools to your Grype branch in `tests/quality/config.yaml`.**

If you wanted to see PR quality gate checks pass with your specific Grype changes (if you have any) then you can update the
`yardstick.tools[*]` entries for grype to use the a version that points to your fork (w.g. `your-fork-username/grype@main`).
If you don't have any grype changes needed then you can skip this step.


#### **5. In Vunnel: add new "vulnerability match labels" to annotate True and False positive findings with Grype.**

In order to evaluate the quality of the new provider, we need to know what the expected results are. This is done by
annotating Grype results with "True Positive" labels (good results) and "False Positive" labels (bad results). We'll use
[Yardstick](github.com/anchore/yardstick) to do this:

```bash
$ cd tests/quality

# capture results with the development version of grype (from your fork)
$ make capture provider=<your-provider-name>

# list your results
$ uv run yardstick result list | grep grype

d415064e-2bf3-4a1d-bda6-9c3957f2f71a  docker.io/anc...  grype@v0.58.0             2023-03...
75d1fe75-0890-4d89-a497-b1050826d9f6  docker.io/anc...  grype[custom-db]@bdcefd2  2023-03...

# use the "grype[custom-db]" result UUID and explore the results and add labels to each entry
$ uv run yardstick label explore 75d1fe75-0890-4d89-a497-b1050826d9f6

# You can use the yardstick TUI to label results:
# - use "T" to label a row as a True Positive
# - use "F" to label a row as a False Positive
# - Ctrl-Z to undo a label
# - Ctrl-S to save your labels
# - Ctrl-C to quit when you are done

```

Later we'll open a PR in the [vulnerability-match-labels repo](github.com/anchore/vulnerability-match-labels) to persist these labels.
For the meantime we can iterate locally with the labels we've added.


#### **6. In Vunnel: run the quality gate.**

```bash
cd tests/quality

# runs your specific provider to gather vulnerability data, builds a DB, and runs grype with the new DB
make capture provider=<your-provider-name>

# evaluate the quality gate
make validate
```

This uses the latest Grype-DB release to build a DB and the specified Grype version with a DB containing only data from the new provider.

You are looking for a passing run before continuing further.


#### **7. Open a [vulnerability-match-labels repo](github.com/anchore/vulnerability-match-labels) PR to persist the new labels.**

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


#### **8. In Vunnel: open a PR with your new provider.**

The PR will also run all of the same quality gate checks that you ran locally.

If you have Grype changes, you should also create a PR for that as well. The Vunnel PR will not pass PR checks until the Grype PR is merged and the `test/quality/config.yaml` file is updated to point back to the `latest` Grype version.


### ...for a new schema

This is the same process as listed above with a few additional steps:

1. You will need to add the new schema to the Vunnel repo in the `schemas` directory.
2. Grype-DB will need to be updated to support the new schema in the `pkg/provider/unmarshal` and `pkg/process/v*` directories.
3. The Vunnel `tests/quality/config.yaml` file will need to be updated to use development `grype-db.version`, pointing to your fork.
4. The final Vunnel PR will not be able to be merged until the Grype-DB PR is merged and the `tests/quality/config.yaml` file is updated to point back to the `latest` Grype-DB version.


## What might need refactoring?

Looking to help out with improving the code quality of Vunnel, but not sure where to start?

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
