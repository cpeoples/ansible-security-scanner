# Releasing Ansible Security Scanner

This project publishes to [PyPI](https://pypi.org/project/ansible-security-scanner/)
via **Trusted Publishing** (OIDC). There are no long-lived API tokens, and the
package version is derived automatically from git tags.

## One-time setup (done once per PyPI account)

### 1. PyPI trusted publishers

Add a trusted publisher on both indexes using the values below:

- **PyPI** - https://pypi.org/manage/account/publishing/
- **TestPyPI** - https://test.pypi.org/manage/account/publishing/

| Field | Value |
|---|---|
| PyPI Project Name | `ansible-security-scanner` (lowercase, hyphenated; must match `pyproject.toml`) |
| Owner | `cpeoples` |
| Repository name | `ansible-security-scanner` |
| Workflow name | `scanner-release.yml` |
| Environment name | `pypi` (PyPI) **or** `testpypi` (TestPyPI) - use exactly one per publisher |

Two publishers total: one with environment `pypi` configured on pypi.org, a
second with environment `testpypi` configured on test.pypi.org.

### 2. GitHub environments

Create two environments in the repo settings
(`Settings -> Environments -> New environment`):

- `testpypi` - no protection rules needed (automatic).
- `pypi` - add `Required reviewers` (at least one maintainer) so prod publishes
  require an explicit click. Recommended. Optional but strongly encouraged.

## Cutting a release

All versions are PEP 440 (`MAJOR.MINOR.PATCH` with optional pre-release
suffixes like `1.0.0rc1`).

### 1. Pre-flight (on your workstation)

```bash
git checkout main
git pull
.venv/bin/python -m pytest          # must be green
.venv/bin/python -m build           # must succeed locally
```

### 2. Tag the release

Always use annotated tags so metadata (date, author, message) is preserved:

```bash
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0
```

### 3. Create the GitHub Release

```bash
gh release create v1.0.0 \
  --generate-notes \
  --title "v1.0.0"
```

Or via the UI: **Releases -> Draft a new release -> pick `v1.0.0` -> Publish
release**.

### 4. Watch the pipeline

Publishing the GitHub Release fires `scanner-release.yml`:

```
build           -> produces dist/ansible_security_scanner-1.0.0-py3-none-any.whl
publish-testpypi -> OIDC -> TestPyPI
smoke-test      -> clean runner installs from TestPyPI, verifies CLI + SBOM formatter
publish-pypi    -> manual approval gate (if configured) -> OIDC -> PyPI
sign-and-attest -> Sigstore signatures + SLSA build provenance attached to the Release
```

If TestPyPI smoke-test fails, `publish-pypi` is skipped automatically.

### 5. Dry-running a release

To publish only to TestPyPI without creating a GitHub Release:

```
Actions -> Scanner Release -> Run workflow -> publish_pypi = false
```

This runs build -> TestPyPI -> smoke-test, then stops.

## Versioning rules

- **Patch bumps** (`v1.0.1`) - bug fixes only.
- **Minor bumps** (`v1.1.0`) - new features, backward-compatible.
- **Major bumps** (`v2.0.0`) - breaking changes to public CLI flags, output
  schemas, or API.

The version is derived from the tag by `hatch-vcs`; never edit a version
number by hand in `pyproject.toml` or `_version.py`.

## Rolling back

PyPI does not allow re-uploading the same version. If a release is broken,
yank it from PyPI (`pip install` will still work for pinned users but no new
installs will pick it up) and ship a new patch version:

```bash
git tag -a v1.0.1 -m "Release 1.0.1 - hotfix for ..."
git push origin v1.0.1
gh release create v1.0.1 --generate-notes --title "v1.0.1"
```

Never force-push a tag. Never delete a tag that has been published. Both
break reproducible installs for downstream users.
