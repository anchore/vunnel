## Releasing

Vunnel is published as:
- a git tag in the repo
- a `ghcr.io/anchore/vunnel` docker image

There are two times when assets are released:

- when a new commit reaches main:
    - a new `ghcr.io/anchore/vunnel:[GIT-COMMIT]` docker image is published
    - a build is published to the [testpypi project](https://test.pypi.org/project/vunnel/)

- when a release is triggered:
    - the commit on main is tagged with the given version
    - the existing commit-based image is additionally tagged as `ghcr.io/anchore/vunnel:[VERSION]` and `ghcr.io/anchore/vunnel:latest`
    - a build is published to the [pypi project](https://pypi.org/project/vunnel/)

## Creating a new release

You can release vunnel by running `make release` (if you have the appropriate repo permissions).

You do **not** need to use this local trigger script. You can always kick off the release from the GitHub actions UI as a workflow_dispatch, inputting the desired new version for the release. This approach acts as a manual override for the version if `chronicle` is non-functional or the issue/PR labels are not ready but a release is urgently needed. Remember, if you go this approach you will need to check the release notes afterwards and manually tailor as-needed.

## Managing release versions

This project uses [`chronicle`](https://github.com/anchore/chronicle) to determine the next release from the current set of issues closed and PRs merged since the last release. The kind of change is determined by the set of issue labels, for example the `enhancement` label applied to a closed issue will bump the minor version and the label `bug` applied to a closed issue will bump the patch version. See the [default chronicle change definitions](https://github.com/anchore/chronicle#default-github-change-definitions) for more guidance on how labels affect the changelog. PRs can also be directly included, however, they are superseded by any closed issues that are also linked.

The changelog is also generated with chronicle, collecting changes of particular kinds together with the issue/PR title acting as the changelog entry summary.

If you close an issue with the label `wont-fix` or `changelog-ignore` then the issue will be excluded from consideration while creating the version and changelog.

Why go this approach? The basic idea is that **if you keep issues and PRs well organized and linked (as should be done anyway) then you get version management and changelogs for free**!

The python package version is managed by [`dunamai`](https://github.com/mtkennerly/dunamai) and derives the answer from a single-source of truth (the git tag) but additionally manages how that version propagates to the `pyproject.toml` and other places in the final build. The version within the `pyproject.toml` in the git repo should remain as `v0.0.0`.
