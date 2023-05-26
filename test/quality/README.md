# Match quality testing

This form of testing compares the results from various releases of griffon using a
static set of reference container images. The kinds of comparisons made are:

1) "relative": find the vulnerability matching differences between both tools
   for a given image. This helps identify when a change has occurred in matching
   behavior and where the changes are.

2) "against labels": pair each tool results for an image with ground truth. This
   helps identify how well the matching behavior is performing (did it get
   better or worse).


## Getting started

For information about required setup see: [Required setup](#required-setup).

To capture raw tool output and store into the local `.yardstick` directory for
further analysis:
```
make capture
```

To analyze the tool output and evaluate a pass/fail result:
```
make validate
```

A pass/fail result is shown in the output with reasons for the failure being
listed explicitly.


## What is the quality gate criteria

The label comparison results are used to determine a pass/fail result,
specifically with the following criteria:

 - fail when current griffon F1 score drops below last griffon release F1 score (or
   F1 score is indeterminate)
 - fail when the indeterminate matches % > 10% in the current griffon results
 - fail when there is a rise in FNs relative to the results from the last griffon
   release
 - otherwise, pass

F1 score is the primary way that tool matching performance is characterized. F1
score combines the TP, FP, and FN counts into a single metric between 0 and 1.
Ideally the F1 score for an image-tool pair should be 1. F1 score is a good way
to summarize the matching performance but does not explain why the matching
performance is what it is.

Indeterminate matches are matches from results that could not be pared with a
label (TP or FP). This could also mean that multiple conflicting labels were
found for the a single match. The more indeterminate matches there are the less
confident you can be about the F1 score. Ideally there should be 0 indeterminate
matches, but this is difficult to achieve since vulnerability data is constantly
changing. 

False negatives represent matches that should have been made by the tool but
were missed. We should always make certain that this value does not increase
between releases of griffon.

## Assumptions

1. **Comparing vulnerability results taken at different times is invalid**.
   We leverage the yardstick result-set feature to capture all vulnerability
   results at one time for a specific image and tool set. Why? If we use griffon
   at version `a` on monday and griffon at version `b` on tuesday and attempt to
   compare the results, if differences are found it will not be immediately
   clear why the results are different. That is, it is entirely possible that
   the vulnerability databases from the run of `b` simply had more up to date
   information, and if `griffon@a` were run at the same time (on tuesday) this
   reason can be almost entirely eliminated.

2. **Comparing vulnerability results across images with different digests is invalid**.
   It may be very tempting to compare vulnerability results for
   `alpine:3.2` from monday and `alpine:3.2` from tuesday to see if there are
   any changes. However, this is potentially inaccurate as the image references
   are for the same tag, but the publisher may have pushed a new image with
   differing content. Any change could lead to different vulnerability matching
   results but we are only interested in vulnerability match differences that
   are due to actionable reasons (griffon matcher logic problems or [SBOM] input
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
  allows for <= 2020). Though there are still retroactive CVEs created, this
  helps a lot in terms of keeping vulnerability results relatively stable.

- SBOMs are used as input into griffon instead of the raw container images. This
  allows the artifacts under test to remain truly fixed and saves a lot of time
  when capturing griffon results (as the container image is no longer needed
  during analysis).

- For the captured SBOMs, container images referenced must be with a digest, not
  just a tag. In case we update a tool version (say syft) we want to make
  certain that we are scanning the exact same artifact later when we re-run the
  analysis.

- Versions of tools used are fixed to a specific `major.minor.patch` release used.
  This allows us to account for capability differences between tool runs.


To reduce maintenance effort of this comparison over time there are a few things 
to keep in mind:

- Once an image is labeled (at a specific digest) the image digest should be
  considered immutable (never updated). Why? It takes a lot of effort to label
  images and there are no "clearly safe" assumptions that can be made when it
  comes to migrating labels from one image to another no matter how "similar"
  the images may be. There is also no value in updating the image; these images
  are not being executed and their only purpose is to survey the matching
  performance of griffon. In the philosophy of "maximizing fixed points" it
  doesn't make sense to change these assets. Over time it may be that we remove
  assets that are no longer useful for comparison, but this should rarely be
  done.

- Consider not changing the CVE year max-ceiling (currently set to 2020).
  Pushing this ceiling will likely raise the number of unlabled matches
  significantly for all images. Only bump this ceiling if all possible matches
  are labeled.

## Workflow

One way of working is to simply run `yardstick` and `gate.py` in the `test/quality` directory.
You will need to make sure the `vulnerabilty-match-labels` submodule has been initialized. This happens automatically
for some `make` commands, but you can ensure this by `git submodule update --init`. After the submodule has been
initialized, the match data from `vulnerabilty-match-labels` will be available locally.

**TIP**: when dealing with submodules, it may be convenient to set the git config option `submodule.recurse` to `true`
so `git checkout` will automatically update submodules to the correct commit:
```shell
git config submodule.recurse true
```

To do this we need some results to begin with. As noted above, start with (this does ensure the submodule is initialized):
```shell
make capture
```

This will download prebuilt SBOMs for the configured images and generate match results for configured tools (here:
the previous Grype version as well as the local version).

After `make capture` has finished, we should have results and can now start inspecting and
modifying the comparison labels.

To get started, let's assume we see some quality gate failure in like this (something found in CI
or after running `./gate.py`):
```
Running comparison against labels... 
   Results used:
    ├── f4fb4e6e-c911-41b6-9a10-f90b3954a41a : griffon@v0.53.1-19-g8900767 against docker.io/anchore/test_images@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9
    └── fcebdd0b-d80a-4fe2-b81a-802c7b98d83b : griffon@v0.53.1 against docker.io/anchore/test_images@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9

Match differences between tooling (with labels):
   TOOL PARTITION      PACKAGE       VULNERABILITY   LABEL         COMMENTARY
   griffon@v0.53.1 ONLY  node@14.18.2  CVE-2021-44531  TruePositive  (this is a new FN 😱)
   griffon@v0.53.1 ONLY  node@14.18.2  CVE-2021-44532  TruePositive  (this is a new FN 😱)
   griffon@v0.53.1 ONLY  node@14.18.2  CVE-2021-44533  TruePositive  (this is a new FN 😱)

Failed quality gate
   - current F1 score is lower than the latest release F1 score: current=0.80 latest=0.80 image=docker.io/anchore/test_images@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9
   - current indeterminate matches % is greater than 10%: current=13.60% image=docker.io/anchore/test_images@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9
   - current false negatives is greater than the latest release false negatives: current=6 latest=3 image=docker.io/anchore/test_images@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9
```

This tells us some important information: which package, version, and vulnerability had a difference;
how it was previously labeled, and most importantly: the image we need to focus on (`docker.io/anchore/test_images@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9`).

Using the SHA above, we can run `yardstick` to see which results are available:
```shell
$ yardstick result list --result-set pr_vs_latest_via_sbom | grep 808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9

5bf0611b-183f-4525-a1ab-f268f62f48b6  docker.io/anchore/test_images:appstreams-centos-stream-8-1a287dd@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9          griffon@v0.53.1              2022-12-09 20:49:56+00:00
43a9650a-d5de-4687-b3ba-459105e32cb8  docker.io/anchore/test_images:appstreams-centos-stream-8-1a287dd@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9          griffon@v0.53.1-15-gf29a32b  2022-12-09 20:49:53+00:00
67913f57-690f-4f35-a2d9-ffccd2a0b2a1  docker.io/anchore/test_images:appstreams-centos-stream-8-1a287dd@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9          syft@v0.60.1               2022-11-01 20:30:52+00:00
```

We'll need to use the UUIDs to explore the labels, so copy the first UUID, which we can see was run against the last Grype release (`griffon@v0.53.1`). Use the UUID to explore and edit the results with
`yardstick label explore`:
```shell
yardstick label explore 5bf0611b-183f-4525-a1ab-f268f62f48b6
```

At this point we can use the TUI to explore and modify the match data, by deleting things or labeling as
true positives, false positives, etc.. **After making changes make sure to save the results** (`Ctrl-S`)!

At this point you can run the quality gate using updated label data. The quality gate can run against 
just one image, for example the image we first found in the failure, so run the quality gate and see
how changes to the label data have affected the result:
```shell
./gate.py --image docker.io/anchore/test_images@sha256:808f6cf3cf4473eb39ff9bb47ead639d2ed71255b75b9b140162b58c6102bcc9
```

After iterating on all the changes we need using `yardstick label explore`, we're now ready to commit changes. Since
we're using `git submodules`, we need to do two steps:
1. get the changes merged to the `vulnerability-match-labels` repository `main` branch
2. update the submodule in this repository

To create a pull request for the `vulnerability-match-labels`, make sure you are in the `vulnerability-match-labels`
subdirectory and create a branch -- something like:
```shell
git checkout --no-track -b my-branch-name
```

Commit the changes to this branch, push, create a pull request like normal. NOTE: you may need to add a fork
(`git remote add ...`) and push to the fork if you don't have push permissions against the main
`vulnerability-match-labels` repo. After the PR is approved and merged to `vulnerability-match-labels` repo's `main`
branch, update the submodule locally using:
```shell
git submodule update --remote
```

Next, _commit the submodule change_ as part of any other changes 
to the Grype pull request and push as part of the in-progress PR
against Grype. The PR will now use the updated match labels when running
the quality check.

## Required setup

In order to manage Python versions, [pyenv](https://github.com/pyenv/pyenv) can be used. (e.g. `brew install pyenv`)

Both this project and `yardstick` require Python 3.10.

Using `pyenv`, see which python versions are available, for example:
```shell
$ pyenv install --list|grep 3.10
  3.10.0
  ...
  3.10.7
  ...
```

In this case, we see `3.10.7` is the latest version, so we'll use that for the rest of the setup:

Install this version using `pyenv`:
```shell
pyenv install 3.10.7
```

NOTE: to view the specific Python versions installed use `pyenv versions`:
```shell
$ pyenv versions
  system
* 3.8.13 (set by /Users/usr/.pyenv/version)
  3.10.7
```

To select the `3.10` version use the exact version number:
```shell
pyenv shell 3.10.7
```

(or maybe just: `pyenv shell $(pyenv versions | grep 3.10 | tail -1)`)

Verify this has worked properly by running:
```shell
python --version
```

**Important:** it is also required to have `oras` installed (e.g. `brew install oras`)

**After** setting the working Python version to 3.10, in the `test/quality` directory,
you need to set up a virtual environment using:
```shell
make venv
```

**After** creating the virtual environment, you can now activate it to set up a
working shell using:
```shell
. venv/bin/activate
```

You should now have a shell running in the correct virtual environment, it might look something
like this:
```shell
(venv) user@HOST quality %
```

Now you should be able to run both `yardstick` and `./gate.py`.

## Troubleshooting

As noted above, yardstick requires Python 3.10. If you try to run with an older version, such as
the default macOS 3.8 version, you will likely see an error similar to:

```
Traceback (most recent call last):
  File "./vulnerability-match-labels/sboms.py", line 12, in <module>
    import yardstick
  File "/griffon/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/__init__.py", line 4, in <module>
    from . import arrange, artifact, capture, cli, comparison, label, store, tool, utils
  File "/griffon/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/arrange.py", line 4, in <module>
    from yardstick import artifact
  File "/griffon/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/artifact.py", line 482, in <module>
    class ResultSet:
  File "/griffon/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/artifact.py", line 484, in ResultSet
    state: list[ResultState] = field(default_factory=list)
TypeError: 'type' object is not subscriptable
```
