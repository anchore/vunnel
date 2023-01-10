## Releasing

Vunnel is published as:
- a git tag in the repo
- a `ghcr.io/anchore/vunnel` docker image

There are two times when assets are released:

- when a new commit reaches main:
    - a new `ghcr.io/anchore/vunnel:[GIT-COMMIT]` docker image is published

- when a release is triggered:
    - the commit on main is tagged with the given version
    - the existing commit-based image is additionally tagged as `ghcr.io/anchore/vunnel:[VERSION]`


## Creating a new release

You can release vunnel by running `make trigger-release` (if you have the appropriate repo permissions):
```
$ make trigger-release

Proposed version: v0.1.0

   Changelog

  ## v0.1.0 https://github.com/anchore/vunnel/tree/v0.1.0 (2023-01-10)

  Full Changelog https://github.com/anchore/vunnel/compare/v0.0.0...v0.1.0

  ### Added Features

  • Port remaining feed drivers from enterprise [Issue #3 https://github.com/anchore/vunnel/issues/3]

  ### Bug Fixes

  • NVD provider taking a long time even when results are cached [Issue #9 https://github.com/anchore/vunnel/issues/9]

Do you want to trigger a release with this version? [y/n] y

Kicking off release for v0.1.0...
✓ Created workflow_dispatch event for release.yaml at main

To see runs for this workflow, try: gh run list --workflow=release.yaml

Waiting for release to start...
Head to the release workflow to monitor the release: https://github.com/anchore/vunnel/actions/runs/3885067293

✓ main Release · 3885067293
Triggered via workflow_dispatch about 1 minute ago

JOBS
✓ quality-gate in 48s (ID 10556082455)
  ✓ Set up job
  ✓ Run actions/checkout@v3
  ✓ Check if tag already exists
  ✓ Ensure tagged commit is on main
  ✓ Check validation results
  - Quality gate
  ✓ Post Run actions/checkout@v3
  ✓ Complete job
✓ release in 43s (ID 10556109730)
  ✓ Set up job
  ✓ Run actions/checkout@v3
  ✓ Run actions/setup-python@v4
  ✓ Install poetry
  ✓ Cache Poetry virtualenv
  ✓ Setup Poetry config
  ✓ Restore tool cache
  - (cache-miss) Bootstrap tools
  ✓ Install dependencies and package
  ✓ Login to ghcr.io
  ✓ Tag release
  ✓ Promote commit image to release
  ✓ Create github release
  ✓ Post Restore tool cache
  ✓ Post Cache Poetry virtualenv
  ✓ Post Run actions/checkout@v3
  ✓ Complete job
  ✓ Post Run actions/setup-python@v4

✓ Run Release (3885067293) completed with 'success'
```

You do **not** need to use this local trigger script. You can always kick off the release from the GitHub actions UI as a workflow_dispatch, inputting the desired new version for the release. This approach acts as a manual override for the version if `chronicle` is non-functional or the issue/PR labels are not ready but a release is urgently needed. Remember, if you go this approach you will need to check the release notes afterwards and manually tailor as-needed.

## Managing release versions

This project uses [`chronicle`](https://github.com/anchore/chronicle) to determine the next release from the current set of issues closed and PRs merged since the last release. The kind of change is determined by the set of issue labels, for example the `enhancement` label applied to a closed issue will bump the minor version and the label `bug` applied to a closed issue will bump the patch version. See the [default chronicle change definitions](https://github.com/anchore/chronicle#default-github-change-definitions) for more guidance on how labels affect the changelog. PRs can also be directly included, however, they are superseded by any closed issues that are also linked.

The changelog is also generated with chronicle, collecting changes of particular kinds together with the issue/PR title acting as the changelog entry summary.

If you close an issue with the label `wont-fix` or `changelog-ignore` then the issue will be excluded from consideration while creating the version and changelog.

Why go this approach? The basic idea is that **if you keep issues and PRs well organized and linked (as should be done anyway) then you get version management and changelogs for free**!

The python package version is managed by [`dunamai`](https://github.com/mtkennerly/dunamai) and derives the answer from a single-source of truth (the git tag) but additionally manages how that version propagates to the `pyproject.toml` and other places in the final build. The version within the `pyproject.toml` in the git repo should remain as `v0.0.0`.
