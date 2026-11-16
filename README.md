# vunnel

**A tool for fetching, transforming, and storing vulnerability data from a variety of sources.**

[![GitHub release](https://img.shields.io/github/release/anchore/vunnel.svg)](https://github.com/anchore/vunnel/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/vunnel/blob/main/LICENSE)
[![Join our Discourse](https://img.shields.io/badge/Discourse-Join-blue?logo=discourse)](https://anchore.com/discourse)

![vunnel-demo](https://user-images.githubusercontent.com/590471/226942827-e19742ef-e66e-4e11-8f9b-fb74c40f1dee.gif)

Supported data sources:
- Alpine (https://secdb.alpinelinux.org)
- Amazon (https://alas.aws.amazon.com/AL2/alas.rss & https://alas.aws.amazon.com/AL2022/alas.rss)
- Azure (https://github.com/microsoft/AzureLinuxVulnerabilityData)
- Debian (https://security-tracker.debian.org/tracker/data/json & https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DSA/list)
- Echo (https://advisory.echohq.com/data.json)
- GitHub Security Advisories (https://api.github.com/graphql)
- GitHub repository security advisories not yet in the GitHub Advisory Database (https://api.github.com/repos/{owner}/{repo}/security-advisories)
- NVD (https://services.nvd.nist.gov/rest/json/cves/2.0)
- Oracle (https://linux.oracle.com/security/oval)
- RedHat (https://www.redhat.com/security/data/oval)
- SLES (https://ftp.suse.com/pub/projects/security/oval)
- Ubuntu (https://launchpad.net/ubuntu-cve-tracker)
- Wolfi (https://packages.wolfi.dev)


## Prerequisites

The following system tools must be available on your PATH:
- **git** - Required by some providers that fetch data from git repositories

## Installation

With pip:

```bash
pip install vunnel
```

With docker:

```bash
docker run \
  --rm -it \
  -v $(pwd)/data:/data \
  -v $(pwd)/.vunnel.yaml:/.vunnel.yaml \
    ghcr.io/anchore/vunnel:latest  \
      run nvd
```
Where:
  - the `data` volume keeps the processed data on the host
  - the `.vunnel.yaml` uses the host application config (if present)
  - you can swap `latest` for a specific version (same as the git tags)

See [the vunnel package](https://github.com/anchore/vunnel/pkgs/container/vunnel) for a full listing of available tags.


## Getting Started

List the available vulnerability data providers:

```
$ vunnel list

alpine
amazon
chainguard
debian
echo
github
github_repo
mariner
minimos
nvd
oracle
rhel
sles
ubuntu
wolfi
```

Download and process a provider:

```
$ vunnel run wolfi

2023-01-04 13:42:58 root [INFO] running wolfi provider
2023-01-04 13:42:58 wolfi [INFO] downloading Wolfi secdb https://packages.wolfi.dev/os/security.json
2023-01-04 13:42:59 wolfi [INFO] wrote 56 entries
2023-01-04 13:42:59 wolfi [INFO] recording workspace state
```

You will see the processed vulnerability data in the local `./data` directory

```
$ tree data

data
└── wolfi
    ├── checksums
    ├── metadata.json
    ├── input
    │   └── secdb
    │       └── os
    │           └── security.json
    └── results
        └── wolfi:rolling
            ├── CVE-2016-2781.json
            ├── CVE-2017-8806.json
            ├── CVE-2018-1000156.json
            └── ...
```

*Note: to get more verbose output, use `-v`, `-vv`, or `-vvv` (e.g. `vunnel -vv run wolfi`)*

Delete existing input and result data for one or more providers:

```
$ vunnel clear wolfi

2023-01-04 13:48:31 root [INFO] clearing wolfi provider state
```

Example config file for changing application behavior:

```yaml
# .vunnel.yaml
root: ./processed-data

log:
  level: trace

providers:
  wolfi:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 10

```

Use `vunnel config` to get a better idea of all of the possible configuration options.

### Tracking unmerged GitHub repository advisories (`github_repo`)

When a maintainer publishes a security advisory on a GitHub repository, it is visible on the repository's
Security tab immediately, but it only reaches the global GitHub Advisory Database (and therefore the `github`
provider) after GitHub has reviewed it, which can take weeks. The `github_repo` provider closes that gap for a
list of repositories you choose:

```yaml
# .vunnel.yaml
providers:
  github_repo:
    # optional, but strongly recommended: unauthenticated requests are limited to 60 per hour
    token: env:GITHUB_TOKEN
    repos:
      - netty/netty
      - https://github.com/FasterXML/jackson-databind
```

How it behaves:

- Only **published** advisories are considered; draft, triage, closed and withdrawn advisories are ignored. Only
  publicly visible data is used, so the token needs no scopes.
- Advisories that are already in the GitHub Advisory Database (reviewed or malware) are skipped. Once an advisory
  is merged it disappears from `github_repo` output on the next run and the `github` provider becomes its source.
  Merged advisory IDs are cached in the provider's input directory so they are not re-checked.
- Records use the same schema and `github:<ecosystem>` namespaces as the `github` provider, so they are consumed
  identically downstream. The advisory `url` points at the repository's advisory page, since the global advisory
  URL does not resolve until the advisory is merged.
- Every run is a full refresh (results are deleted before writing). Missing or renamed repositories are logged
  and skipped; malformed `repos` entries fail at configuration load.
- An advisory can briefly appear in both providers if GitHub merges it after a `github_repo` run but before a
  `github` run; both records carry the same GHSA ID and equivalent content.


## FAQ


### Can I implement a new provider?

Yes you can! See [the provider docs](https://github.com/anchore/vunnel/blob/main/DEVELOPING.md#adding-a-new-provider) for more information.


### Why is it called "vunnel"?

This tool "funnels" vulnerability data into a single spot for easy processing... say "vulnerability data funnel" 100x fast enough and eventually it'll slur to "vunnel" :).
