# Match quality testing

The quality gate checks that a vunnel change does not make grype's matching worse. For each provider it builds a grype DB from this checkout's vunnel (plus cached data for any other providers the test needs), scans the provider's test images with grype `main` against that DB and against a published DB, and scores both scans against labels with [yardstick](https://github.com/anchore/yardstick).

- `config.yaml` is the source of truth: the images, validations and expected namespaces per provider, and the reference DB.
- `configure.py configure <provider>` turns it into a yardstick gate at `gates/<provider>.yaml` (generated, not committed).
- Labels and SBOMs come from [anchore/claims](https://github.com/anchore/claims), then grype's `test/integration/additional-claims`, then this repo's `additional-claims/`, in that order (`.yardstick.yaml`). A later source wins on the same label.
- yardstick, grype and grype-db are pinned in `tests/integration/.binny.yaml` and installed into `tests/integration/.tool/` by `make integration:tools`. They stay out of the repo root's `.binny.yaml`, so formatting and linting never build them.
- The gate's tasks live in `tasks.d/integration.yaml` (the `integration:` namespace), run from the repo root (`make help` lists them).

## Getting started

```
make integration PROVIDER=alpine                 # run every integration suite (the quality gate, so far)
make integration:quality:db PROVIDER=alpine      # build a DB for the provider from this checkout
make integration:quality PROVIDER=alpine         # get SBOMs, scan with both setups and score; exits 1 when the gate fails
make integration:quality:score PROVIDER=alpine   # re-score the last scans against the current labels, without scanning
```

Each installs the gate's tools first: yardstick from its GitHub release, grype and grype-db with `go install`. `make integration:quality:db` pulls cached provider data from `ghcr.io`, so it needs Go and an `oras login ghcr.io`.

## What is the quality gate criteria

Each provider's validation in `config.yaml` maps to the gate's checks, evaluated per image:

 - `max_f1_regression` -> `f1NotWorse`: the candidate's F1 may not drop below the reference's by more than this
 - `max_new_false_negatives` -> `noNewFalseNegatives`: true positives the reference found and the candidate misses
 - `fail_on_empty_match_set` (default true) -> `matchesAtLeast {min: 1}`: the candidate and the reference together must match something on each image. `false` gives `min: 0`, which turns the check off (yardstick adds `min: 1` to a gate that leaves it out)
 - `max_year` and `expected_namespaces` filter which matches and labels count at all

A check that unlabeled matches leave undecided does not fail the gate (`undecided: pass`), since these gates are diff-based and only a decided regression should fail them.

F1 score is the primary way that tool matching performance is characterized. F1 score combines the TP, FP, and FN counts into a single metric between 0 and 1. It summarizes the matching performance but does not explain why it is what it is.

False negatives represent matches that should have been made by the tool but were missed. This value should never increase.

## Assumptions

1. **Comparing vulnerability results taken at different times is invalid**.
   Both setups of a gate are scanned in the same run. Why? If we use grype
   at version `a` on monday and grype at version `b` on tuesday and attempt to
   compare the results, if differences are found it will not be immediately
   clear why the results are different. That is, it is entirely possible that
   the vulnerability databases from the run of `b` simply had more up to date
   information, and if `grype@a` were run at the same time (on tuesday) this
   reason can be almost entirely eliminated.

2. **Comparing vulnerability results across images with different digests is invalid**.
   It may be very tempting to compare vulnerability results for
   `alpine:3.2` from monday and `alpine:3.2` from tuesday to see if there are
   any changes. However, this is potentially inaccurate as the image references
   are for the same tag, but the publisher may have pushed a new image with
   differing content. Any change could lead to different vulnerability matching
   results but we are only interested in vulnerability match differences that
   are due to actionable reasons (grype matcher logic problems or [SBOM] input
   data into matchers).

## Approach

Vulnerability matching has essentially two inputs:

- the packages that were found in the scanned artifact

- the vulnerability data from upstream providers (e.g. NVD, GHSA, etc.)


These are both moving targets!


We may implement more catalogers in syft that raise up more packages discovered
over time (for the same artifact scanned). Also the world is continually finding
and reporting new vulnerabilities. The more moving parts there are in this form
of testing the harder it is to come to a conclusion about the actual quality of
the output over time.


To reduce the eroding value over time we've decided to change as many moving
targets into fixed targets as possible:

- Vulnerability results beyond a particular year are ignored (the current config
  allows for <= 2021). Though there are still retroactive CVEs created, this
  helps a lot in terms of keeping vulnerability results relatively stable.

- SBOMs are used as input into grype instead of the raw container images. This
  allows the artifacts under test to remain truly fixed and saves a lot of time
  when capturing grype results (as the container image is no longer needed
  during analysis).

- For the captured SBOMs, container images referenced must be with a digest, not
  just a tag. In case we update a tool version (say syft) we want to make
  certain that we are scanning the exact same artifact later when we re-run the
  analysis.

- Both sides scan with the same grype binary (grype `main`, installed by binny
  from `tests/integration/.binny.yaml`), so the only input that differs is the DB.


To reduce maintenance effort of this comparison over time there are a few things
to keep in mind:

- Once an image is labeled (at a specific digest) the image digest should be
  considered immutable (never updated). Why? It takes a lot of effort to label
  images and there are no "clearly safe" assumptions that can be made when it
  comes to migrating labels from one image to another no matter how "similar"
  the images may be. There is also no value in updating the image; these images
  are not being executed and their only purpose is to survey the matching
  performance of grype. In the philosophy of "maximizing fixed points" it
  doesn't make sense to change these assets. Over time it may be that we remove
  assets that are no longer useful for comparison, but this should rarely be
  done.

- Consider not changing the CVE year max-ceiling (currently set to 2021).
  Pushing this ceiling will likely raise the number of unlabled matches
  significantly for all images. Only bump this ceiling if all possible matches
  are labeled.

- If the CVE year max-ceiling needs to be pushed, try to push it only for one
  provider. That is, edit the max-year value on the validation for that
  provider in `tests/integration/config.yaml`.

## Workflow

When the gate fails, `make integration:quality` prints what changed between the two setups, grouped by cause, with the labels each change hits and what labeling the unlabeled ones would do to the verdict. Some failures are real regressions in the provider, and some only need labels.

The commands below run in `tests/integration`, with `yardstick` meaning `.tool/yardstick` there. To label, use the yardstick label UI:

```
yardstick claims serve <provider> --open
yardstick score gates/<provider>.yaml   # re-score with the new labels, no new scans
```

A failed CI run uploads a `qg-capture-state-<provider>` artifact holding the gate file, its scans and `.yardstick.yaml`, and the job summary says how to use it. Extracted into `tests/integration`, it re-scores and labels as above with no DB, no grype and no new scans:

```
unzip qg-capture-state-<provider>.zip && tar -xzf qg-capture-state-<provider>.tar.gz
yardstick score gates/<provider>.yaml -o table
```

New labels are written to `additional-claims/`. Labels only vunnel's gate needs are committed there with the PR that needs them. Generally useful ones belong in [anchore/claims](https://github.com/anchore/claims), by pull request there; the gate reads its `main` branch.

To try a grype, grype-db or yardstick branch, build it over the binary in `tests/integration/.tool/` (`go build -o <vunnel>/tests/integration/.tool/grype-db ./cmd/grype-db` in the grype-db checkout, and the same for the others). CI always uses grype and grype-db `main`, and `make integration:validate-tool-versions` fails if `tests/integration/.binny.yaml` says otherwise.
