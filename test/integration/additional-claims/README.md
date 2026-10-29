# Additional claims

Match labels that belong with grype's quality gate rather than in [anchore/claims](https://github.com/anchore/claims). yardstick reads this directory after anchore/claims, so a label here wins over the same label there, and `yardstick claims serve` writes new labels here.

Labels that are generally useful should move to anchore/claims with a pull request there. vunnel's quality gate also reads this directory from grype's `main` branch (as `test/integration/additional-claims`), so it has to stay in place even when it holds no labels.
