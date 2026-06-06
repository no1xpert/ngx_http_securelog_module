# Deployment Guide — ngx_http_securelog_module v0.9.0-beta

---

## GitHub Deployment

### Step 1 — Initialize local git

```bash
cd ngx_http_securelog_module
git init
git add .
git commit -m "feat: initial release v0.9.0-beta

- AES-256-GCM / GPG / EXT provider support
- Key integrity verification (SHA-256) at nginx startup
- Per-worker log file I/O (no cross-process locking)
- Daily/hourly/size-based log rotation
- CMocka unit tests: 12 cases, all passed
- Verified: NGINX 1.26.3 / Debian 13 / OpenSSL 3.5.5"

git tag v0.9.0-beta
```

### Step 2 — Create GitHub repository

1. github.com → **New repository**
2. Name: `ngx_http_securelog_module`
3. Public
4. README / License / .gitignore: **None** (already included in the package)
5. Create repository

```bash
git remote add origin \
  https://github.com/no1xpert/ngx_http_securelog_module.git
git branch -M main
git push -u origin main
git push origin v0.9.0-beta
```

### Step 3 — Repository settings

GitHub web → repository → **Settings** (About section):

| Field | Value |
|------|--------|
| Description | Real-time encrypted NGINX access logging (AES-256-GCM / GPG / KMS) |
| Website | https://bzlab.dev |
| Topics | `nginx` `security` `encryption` `aes-256-gcm` `gpg` `logging` `nginx-module` `kms` |

### Step 4 — Create GitHub Release

GitHub → **Releases** → **Draft a new release**

| Field | Value |
|------|--------|
| Tag | `v0.9.0-beta` (select existing tag) |
| Title | `v0.9.0-beta — Initial public release` |
| Description | Paste CHANGELOG.md content |
| Attach | `ngx_http_securelog_module_v0.9.0-beta.tar.gz` |
| Pre-release | ✅ Check |

### Step 5 — Set up GitHub Sponsors

```bash
# Add .github/FUNDING.yml
cat > .github/FUNDING.yml << 'FUNDING'
github: no1xpert
FUNDING

git add .github/FUNDING.yml
git commit -m "docs: enable GitHub Sponsors"
git push
```

GitHub → Settings → **Sponsor this project** → Enable

Sponsor tier configuration (GitHub Sponsors settings page):

| Tier | Amount | Benefits |
|------|------|------|
| Individual | $5/mo | Listed in README acknowledgements |
| Startup | $50/mo | Priority issue handling |
| Corporate | $200/mo | Logo in README + quarterly tech consultation |

---

## NGINX Wiki Registration (PR)

### Step 1 — Fork nginx-wiki

1. Visit https://github.com/nginxinc/nginx-wiki
2. Click **Fork** (top right)
3. Fork to your account

### Step 2 — Add module entry file

```bash
git clone https://github.com/no1xpert/nginx-wiki.git
cd nginx-wiki
git checkout -b add-ngx-http-securelog-module

# Create module RST file
cat > source/modules/ngx_http_securelog.rst << 'RST'
ngx_http_securelog_module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:github: `no1xpert/ngx_http_securelog_module`
:author: Bongshin Choi
:license: BSD 2-Clause

Encrypts NGINX HTTP access logs in real-time using AES-256-GCM, GPG,
or a pluggable external KMS/HSM provider. Plaintext never touches disk.

Supports D'Amo, PKCS#11, and cloud KMS integration via the EXT provider
interface. Addresses GDPR Art.32, PCI-DSS Req.10, and Korean financial
regulatory requirements (Korea Electronic Financial Supervision Regulation (EFSR)).
RST

git add source/modules/ngx_http_securelog.rst
git commit -m "Add ngx_http_securelog_module — real-time encrypted logging"
git push origin add-ngx-http-securelog-module
```

### Step 3 — Submit Pull Request

1. Visit https://github.com/nginxinc/nginx-wiki
2. **Pull requests** → **New pull request**
3. base: `nginxinc/nginx-wiki:master`
   compare: `no1xpert/nginx-wiki:add-ngx-http-securelog-module`

PR title:
```
Add ngx_http_securelog_module — real-time AES-256-GCM/GPG encrypted logging
```

PR body:
```markdown
## Module

**ngx_http_securelog_module** encrypts NGINX HTTP access logs
in real-time at the log phase. Plaintext never touches disk.

- AES-256-GCM / GPG / pluggable EXT (D'Amo, PKCS#11, cloud KMS)
- Key integrity verification at startup (SHA-256)
- Verified on NGINX 1.26.3, Debian 13

GitHub: https://github.com/no1xpert/ngx_http_securelog_module
```

---

## awesome-nginx Registration (PR)

### Step 1 — Fork and edit

```bash
# Fork: https://github.com/agile6v/awesome-nginx → click Fork

git clone https://github.com/no1xpert/awesome-nginx.git
cd awesome-nginx
git checkout -b add-ngx-http-securelog-module
```

Find the `## Security` section in `README.md` and add one line:

```markdown
- [ngx_http_securelog_module](https://github.com/no1xpert/ngx_http_securelog_module) -
  Real-time AES-256-GCM / GPG / KMS encrypted access logging. Plaintext never touches disk.
  Supports D'Amo, PKCS#11, AWS/GCP/Azure KMS via pluggable EXT interface.
```

```bash
git add README.md
git commit -m "Add ngx_http_securelog_module"
git push origin add-ngx-http-securelog-module
```

### Step 2 — Pull Request

1. Visit https://github.com/agile6v/awesome-nginx → **Pull requests** → **New pull request**
2. PR title: `Add ngx_http_securelog_module — encrypted NGINX logging`

---

## Final Checklist

### GitHub
- [ ] Create repository and push main branch
- [ ] Push v0.9.0-beta tag
- [ ] Create Release (attach tar.gz, check Pre-release)
- [ ] Set 8 Topics tags
- [ ] Fill in About Description
- [ ] Enable GitHub Sponsors (include FUNDING.yml)
- [ ] Verify CI badge works in README

### Registration PRs
- [ ] Submit nginx-wiki PR → `nginxinc/nginx-wiki`
- [ ] Submit awesome-nginx PR → `agile6v/awesome-nginx`

### README Screenshots (improves PR approval rate)
- [ ] `nginx -t` → `test is successful` screen
- [ ] `xxd` → encrypted binary output
- [ ] `securelog_aes_decrypt` → decrypted log output
- [ ] `make run` → `12 test(s). [PASSED]` output

Place screenshots in `docs/screenshots/` and link them below the
`## Verified Environment` section in README to improve PR approval rate.

---

## Post-Release Promotion Channels

| Channel | Content | Timing |
|------|------|------|
| bzlab.dev blog | Technical post (EN) | Right after GitHub release |
| Reddit r/nginx | Link + one-line intro | Right after GitHub release |
| Hacker News (Show HN) | "Show HN: Real-time encrypted NGINX logging module" | After 10+ stars |
| NGINX community forum | Module introduction post | After NGINX Wiki PR merged |
| Security communities (KR) | Korean introduction | When targeting Korean market |
