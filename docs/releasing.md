# Releasing

Releases are fully automated via
[`.github/workflows/scanner-release.yml`](../.github/workflows/scanner-release.yml).
The workflow uses [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC) - there are no long-lived API tokens stored in GitHub secrets.

## One-time setup

1. Create the project on PyPI and TestPyPI (blank projects are fine).
2. On each, add a **Trusted Publisher** pointing at this repo:
   - Owner: `cpeoples`
   - Repository: `ansible-security-scanner` (or wherever this lives)
   - Workflow name: `scanner-release.yml`
   - Environment name: `pypi` (for PyPI) / `testpypi` (for TestPyPI)
3. In GitHub -> Settings -> Environments, create two environments with
   matching names: `pypi` and `testpypi`. Add required reviewers to `pypi`
   if you want a manual approval gate before production uploads.

## Cutting a release

```bash
# 1. Make sure main is green (scanner-ci.yml passed).
# 2. Tag the release commit. The version in the tag is authoritative -
#    hatch-vcs reads it and stamps it into the wheel.
git tag scanner-v1.2.3
git push origin scanner-v1.2.3

# 3. On GitHub -> Releases -> Draft a new release -> pick the tag -> Publish.
```

Publishing the Release triggers:

1. **Build** - produces sdist + wheel, version derived from the git tag.
2. **TestPyPI** - upload via OIDC, then install in a clean Python and verify
   the CLI runs.
3. **PyPI** - production upload (gated by the `pypi` environment if you
   configured reviewers).
4. **Attest** - generates [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance)
   and Sigstore signatures, then attaches them to the GitHub Release so
   consumers can verify the artifact's origin.

Need a dry run? Trigger `scanner-release.yml` manually with
`publish_pypi = false` - it goes to TestPyPI only.
