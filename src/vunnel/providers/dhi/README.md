# Docker Hardened Images provider

The `dhi` provider clones Docker's canonical `docker-hardened-images/advisories`
repository and emits its generated `DHI-` OS-package records as OSV provider
results. It ignores other records in the repository and validates that selected
records use the release-scoped DHI ecosystem and `pkg:apk/dhi` or `pkg:deb/dhi`
package identity expected by Grype's DHI OSV transformer.

Set `runtime.skip_download: true` to process an existing checkout at
`<workspace>/dhi/input/advisories`. Provider metadata records both the source
repository and the exact Git revision used for the run.
