# Releasing `nachos-ssrf`

This document records the truthful release state for the first public PyPI release of
`nachos-ssrf` as of 2026-05-31 UTC.

## Current state

- Package version: `0.1.0`
- Repo: `https://github.com/Nacho-Labs-LLC/nachos-ssrf`
- PyPI project status on 2026-05-31 UTC: `https://pypi.org/pypi/nachos-ssrf/json` returned `404`
- Local artifact verification status on 2026-05-31 UTC:
  - `python3 -m build` produced `dist/nachos_ssrf-0.1.0.tar.gz`
  - `python3 -m build` produced `dist/nachos_ssrf-0.1.0-py3-none-any.whl`
- Release automation status on 2026-05-31 UTC:
  - checked-in publish workflow: `.github/workflows/publish-pypi.yml`
  - chosen publish authority: PyPI trusted publisher via GitHub Actions OIDC
  - remote trusted-publisher registration is still required on PyPI
  - GitHub environment `pypi` still needs to exist with org-controlled approvers
  - no PyPI publish credentials are stored in this repo

## Ownership

- Release operations owner: Chief of Staff tracks release readiness and verification
- Publisher/bootstrap owner: CTO provisions the org-controlled PyPI ownership path
- Required custody rule: the first upload must not leave `nachos-ssrf` under personal-only control

## Chosen publish path

Preferred bootstrap and steady-state release authority:

- PyPI model: pending trusted publisher, not a long-lived API token
- GitHub owner: `Nacho-Labs-LLC`
- GitHub repository: `nachos-ssrf`
- GitHub workflow file: `.github/workflows/publish-pypi.yml`
- GitHub environment: `pypi`
- Release trigger: push tag `v0.1.0` (and future `v*` tags) after the environment and publisher are configured

Why this path:

- It keeps publish authority attached to the org repo and workflow identity instead of a personal token.
- It gives a narrow, auditable first-release path: build/test in CI, then publish from the tag-bound workflow.
- It avoids storing Twine or API-token secrets in GitHub or the repo.

Important constraint:

- A PyPI pending publisher does not reserve the project name until the first successful publish. The external setup and first tagged publish should happen back-to-back.

## First release checklist

1. Create or access an org-controlled PyPI account path for `nachos-ssrf`.
2. In PyPI, register a pending GitHub Actions trusted publisher with these exact fields:
   - project name: `nachos-ssrf`
   - owner: `Nacho-Labs-LLC`
   - repository: `nachos-ssrf`
   - workflow: `.github/workflows/publish-pypi.yml`
   - environment: `pypi`
3. In GitHub, create environment `pypi` on `Nacho-Labs-LLC/nachos-ssrf` and restrict approvals to org-controlled release maintainers.
4. Ensure at least one additional org-controlled owner or maintainer can administer the PyPI project after first publish, whether through a PyPI organization or explicit collaborator ownership.
5. Build fresh artifacts from the repo root:

```bash
python3 -m build
```

6. Publish `0.1.0` by pushing tag `v0.1.0` so `.github/workflows/publish-pypi.yml` performs the first upload through trusted publishing.
7. Record where the publish authority lives:
   - PyPI owners/maintainers
   - PyPI pending/normal trusted-publisher entry for this repo
   - GitHub environment approvers for `pypi`
8. Verify the public install path from a clean environment:

```bash
python3 -m pip install --target /tmp/nachos-ssrf-public-smoke nachos-ssrf
python3 - <<'PY'
import asyncio
import sys

sys.path.insert(0, "/tmp/nachos-ssrf-public-smoke")

from nachos_ssrf import SSRFProtection, SSRFConfig

async def main():
    ssrf = SSRFProtection(SSRFConfig(allowed_domains=["*"]))
    ok = await ssrf.validate_url("https://example.com/")
    blocked = await ssrf.validate_url("http://127.0.0.1/")
    print({"ok_valid": ok.valid, "blocked_valid": blocked.valid, "blocked_errors": blocked.errors})

asyncio.run(main())
PY
```

9. Update `README.md` to remove the "Until the first PyPI release is live" note once PyPI is live.

## Recommended steady-state path

- Preferred future release path: GitHub Actions trusted publisher bound to the Nacho Labs repo
- Keep credentials out of the repository; if a bootstrap token is unavoidable, store it in org-managed custody only
- Release verification should always include:
  - `python3 -m build`
  - clean `pip install nachos-ssrf`
  - import smoke for `SSRFProtection`, `SSRFConfig`, and a localhost-blocked example
