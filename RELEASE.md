# Release

A release of grype comprises:
- a new semver git tag from the current tip of the main branch
- a new [github release](https://github.com/anchore/grype/releases) with a changelog and archived binary assets
- docker images published to `ghcr.io` and `dockerhub`, including multi architecture images + manifest
- [`anchore/homebrew-grype`](https://github.com/anchore/homebrew-grype) tap updated to point to assets in the latest github release

Ideally releasing should be done often with small increments when possible. Unless a
breaking change is blocking the release, or no fixes/features have been merged, a good
target release cadence is between every 1 or 2 weeks.


## Creating a release

This release process itself should be as automated as possible, and has only a few steps:

1. **Trigger a new release with `make release`**. At this point you'll see a preview
   changelog in the terminal. If you're happy with the changelog, press `y` to continue, otherwise
   you can abort and adjust the labels on the PRs and issues to be included in the release and
   re-run the release trigger command.

1. A release admin must approve the release on the GitHub Actions [release pipeline](https://github.com/anchore/grype/actions/workflows/release.yaml) run page.
   Once approved, the release pipeline will generate all assets and publish a GitHub Release.


## Retracting a release

If a release is found to be problematic, it can be retracted with the following steps:

- Deleting the GitHub Release
- Untag the docker images in the `ghcr.io` and `docker.io` registries
- Revert the brew formula in [`anchore/homebrew-grype`](https://github.com/anchore/homebrew-grype) to point to the previous release
- Add a new `retract` entry in the go.mod for the versioned release

**Note**: do not delete release tags from the git repository since there may already be references to the release
in the go proxy, which will cause confusion when trying to reuse the tag later (the H1 hash will not match and there
will be a warning when users try to pull the new release).

