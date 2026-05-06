# Releasing to PyPI

This repo uses PyPI Trusted Publishing (OIDC) so the GitHub Actions release workflow can upload without an API token in repo secrets. The setup is one-time.

## One-time PyPI configuration

1. Sign in to PyPI: https://pypi.org/account/login/
2. Go to https://pypi.org/manage/project/pttools/settings/publishing/
3. Under "Add a new pending publisher", use:
   - PyPI Project Name: `pttools`
   - Owner: `pentest-tools`
   - Repository name: `pentest-tools`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
4. Click "Add"

After this, every `git push origin v*.*.*` triggers `release.yml` and PyPI accepts the upload via OIDC. No API token needed in the repo.

## One-time GitHub configuration

1. https://github.com/pentest-tools/pentest-tools/settings/environments
2. Create environment named `pypi` (matches the workflow's `environment: pypi`)
3. No secrets need to be added; the OIDC token is short-lived per run.

## Cutting a release

1. Bump version in `pyproject.toml` and `VERSION`
2. Add a `## [X.Y.Z]` section to `CHANGELOG.md`
3. Commit: `git commit -m "release: pttools X.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push origin main && git push origin vX.Y.Z`

The `release.yml` workflow builds, runs tests, and publishes to PyPI. Watch progress with `gh run watch`.

## Fallback (if Trusted Publishing isn't yet configured)

If the publish step fails with `invalid-publisher`, fall back to manual upload from a machine with `~/.pypirc` configured:

```bash
rm -rf dist/
python -m build
twine check dist/*
twine upload dist/*
```

## Verify the release

```bash
curl -s https://pypi.org/pypi/pttools/json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['info']['version'])"
# should print the new version

# Smoke-test in a clean venv:
python3 -m venv /tmp/pttools-fresh && /tmp/pttools-fresh/bin/pip install pttools==X.Y.Z
/tmp/pttools-fresh/bin/pttools --version
ls /tmp/pttools-fresh/lib/python*/site-packages/agents/report/templates/  # should show report.html.j2
```

## v0.10.2 → v0.10.3 incident notes

The v0.10.2 tag run failed with `invalid-publisher` because Trusted Publishing was never configured on PyPI side. v0.10.2 is on PyPI from an earlier manual upload (pre-Trusted-Publishing). v0.10.3 was tagged through the normal flow but the GitHub Actions publish step failed for the same reason; the artifact was uploaded manually with `twine` from a machine with `~/.pypirc` configured. After completing the one-time setup above, future tags publish automatically.
