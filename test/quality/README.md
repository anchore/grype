# Match quality testing

This form of testing compares the results from various releases of grype using a
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

 - fail when current grype F1 score drops below last grype release F1 score (or
   F1 score is indeterminate)
 - fail when the indeterminate matches % > 10% in the current grype results
 - fail when there is a rise in FNs relative to the results from the last grype
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
between releases of grype.

## Assumptions

1. **Comparing vulnerability results taken at different times is invalid**.
   We leverage the yardstick result-set feature to capture all vulnerability
   results at one time for a specific image and tool set. Why? If we use grype
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
  allows for <= 2020). Though there are still retroactive CVEs created, this
  helps a lot in terms of keeping vulnerability results relatively stable.

- SBOMs are used as input into grype instead of the raw container images. This
  allows the artifacts under test to remain truly fixed and saves a lot of time
  when capturing grype results (as the container image is no longer needed
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
  performance of grype. In the philosophy of "maximizing fixed points" it
  doesn't make sense to change these assets. Over time it may be that we remove
  assets that are no longer useful for comparison, but this should rarely be
  done.

- Consider not changing the CVE year max-ceiling (currently set to 2020).
  Pushing this ceiling will likely raise the number of unlabled matches
  significantly for all images. Only bump this ceiling if all possible matches
  are labeled.

## Required setup

In order to manage Python versions, [pyenv](https://github.com/pyenv/pyenv) can be used. (e.g. `brew install pyenv`)

Both this project and `yardstick` require Python 3.10. (e.g. `pyenv install 3.10.7`)

It is also required to have `oras` installed (e.g. `brew install oras`)

To view the specific Python versions installed use `pyenv versions`:
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

Now you should be able to run both `yardstick` and `python gate.py`.

## Troubleshooting

As noted above, yardstick requires Python 3.10. If you try to run with an older version, such as
the default macOS 3.8 version, you will likely see an error similar to:

```
Traceback (most recent call last):
  File "./vulnerability-match-labels/sboms.py", line 12, in <module>
    import yardstick
  File "/grype/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/__init__.py", line 4, in <module>
    from . import arrange, artifact, capture, cli, comparison, label, store, tool, utils
  File "/grype/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/arrange.py", line 4, in <module>
    from yardstick import artifact
  File "/grype/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/artifact.py", line 482, in <module>
    class ResultSet:
  File "/grype/test/quality/vulnerability-match-labels/venv/lib/python3.8/site-packages/yardstick/artifact.py", line 484, in ResultSet
    state: list[ResultState] = field(default_factory=list)
TypeError: 'type' object is not subscriptable
```
