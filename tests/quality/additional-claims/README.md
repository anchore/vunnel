# Additional claims

Match labels that belong with vunnel's quality gate rather than in [anchore/claims](https://github.com/anchore/claims). yardstick reads this directory last, after anchore/claims and grype's `test/quality/additional-claims`, so a label here wins over the same label there, and `yardstick claims serve` writes new labels here.

Labels that are generally useful should move to anchore/claims with a pull request there. grype's quality gate also reads this directory from vunnel's `main` branch, so it has to stay in place even when it holds no labels.
