# Match quality testing

The quality gate checks that a grype change does not make matching worse. It scans a fixed set of SBOMs with grype built from this checkout and with the latest grype release, both on the same pinned DB, and scores both scans against labels with [yardstick](https://github.com/anchore/yardstick).

- `gates/*.yaml` are the gates: the images, the two grype setups and the checks. Each gate keeps vulnerabilities up to one year (`vulnerabilities.maxYear`).
- Labels and SBOMs come from [anchore/claims](https://github.com/anchore/claims), named in `.yardstick.yaml`.
- Each gate pins the DB both setups import, by URL and checksum; yardstick downloads and caches it. `make update-quality-gate-db` moves every gate to the latest published DB.
- `.grype.yaml` is the grype config both setups run with (CPE matching on for every ecosystem, `by-cve`).
- yardstick is pinned in the repo's `.binny.yaml` and installed into `.tool/` the first time a task runs it.

## Getting started

From the repo root:

```
make quality          # build grype, get SBOMs, scan with both setups and score; exits 1 when a gate fails
make quality:score    # re-score the last scans against the current labels, without scanning
```

## What is the quality gate criteria

Each gate's checks are evaluated per image:

 - `f1NotWorse`: the candidate's F1 may not drop below the reference's
 - `noNewFalseNegatives`: true positives the reference found and the candidate misses
 - `matchesAtLeast`: the two setups together must match something on each image (off for the 2022 and 2024 gates)

An image both setups report the same matches on passes without looking at labels. A check that unlabeled matches leave undecided does not fail the gate (`undecided: pass`), since the gate is diff-based and only a decided regression should fail it. Many images have well over 10% of their matches unlabeled on the pinned DB, so a matching change is worth labeling even when the gate passes.

F1 score is the primary way that matching performance is characterized. It combines the TP, FP, and FN counts into a single metric between 0 and 1. It summarizes the matching performance but does not explain why it is what it is.

False negatives represent matches that should have been made by grype but were missed. This value should never increase.

## Assumptions

1. **Comparing vulnerability results taken at different times is invalid**. Both setups of a gate are scanned in the same run and with the same pinned DB, so a difference comes from grype and not from newer vulnerability data.

2. **Comparing vulnerability results across images with different digests is invalid**. Two pulls of `alpine:3.2` may be different images, so every image is referenced by digest, and an image's SBOM is built once and kept.

## Approach

Vulnerability matching has two inputs, the packages found in the scanned artifact and the vulnerability data, and both move over time. To keep the comparison meaningful, as many of them as possible are fixed:

- SBOMs are scanned instead of images, built once with a fixed syft version (see `catalog.yaml` in claims) and stored with the labels.
- The DB is pinned, by URL and checksum, in each gate.
- Vulnerabilities after a gate's `maxYear` are ignored. Retroactive CVEs still appear, but this keeps results mostly stable. Only raise a ceiling once the matches it lets in are labeled.
- Once an image is labeled at a digest, the digest never changes. Labels do not carry over between images, however similar.

## Workflow

When the gate fails, `make quality` prints what changed between the two setups, grouped by cause, with the labels each change hits and what labeling the unlabeled ones would do to the verdict. Some failures are real regressions, and some only need labels.

To label, use the yardstick label UI (it needs yardstick from the [installer](https://github.com/anchore/yardstick#installation), since a `go install` build has no UI):

```
mkdir -p claims
yardstick claims serve gates/pr_vs_latest_via_sbom.yaml --claims ./claims --open
yardstick score gates/*.yaml --claims ./claims   # re-score with the new labels, no new scans
```

A failed CI run uploads a `qg-capture-state` artifact holding the gate files, their scans and `.yardstick.yaml`, and the job summary says how to use it. Extracted into `test/quality`, it re-scores and labels as above with no DB, no grype and no new scans:

```
unzip qg-capture-state.zip && tar -xzf qg-capture-state.tar.gz
make -C ../.. quality:score
```

New labels are written to `./claims`. To keep them, open a pull request adding them to [anchore/claims](https://github.com/anchore/claims); the gate reads its `main` branch.
