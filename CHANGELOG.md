# Changelog

All notable changes to this project will be documented in this file.

---

## v0.9.0-beta (2026-06-06)

Initial public beta release. Verified on NGINX 1.26.3 / Debian 13 (Trixie).

### Core
- AES-256-GCM symmetric encryption provider (OpenSSL)
- GPG asymmetric encryption provider (GPGME)
- EXT pluggable provider interface for enterprise KMS/HSM (D'Amo, PKCS#11, cloud KMS)
- Per-worker log file I/O — no cross-process locking, no write collisions
- Log rotation: `daily` / `hourly` / `size:NM`
- Log record fields: ISO-8601 timestamp · IP · method · URI · HTTP version
  · status code · referer · user-agent

### Key Integrity
- `securelog_keygen.sh` generates `aes.key` + `aes.key.sha256` together
- nginx worker verifies SHA-256 hash of loaded key at every startup
- Hash mismatch → EMERG log + worker startup refused
- Hash file absent → WARN log, module continues (backward compatible)

### Build
- Dynamic module: `--add-dynamic-module` (recommended)
- Static module: `--add-module`
- Verified: NGINX 1.26.3, Debian 13, GCC 14.2.0, OpenSSL 3.5.5

### Tools
- `tools/securelog_aes_decrypt.c` — AES-256-GCM binary log decryption utility
- `tools/securelog_keygen.sh` — AES key + hash file generator
- `tools/securelog_ext_provider_template.c` — EXT provider skeleton
  with D'Amo / PKCS#11 integration notes

### Tests (CMocka)
- 12 unit tests, all passing
  - TC-01: AES round-trip (basic)
  - TC-02: Empty plaintext handling
  - TC-03: Large message (>4 KB)
  - TC-04: Tampered ciphertext detection (GCM auth tag)
  - TC-05: Wrong key rejection
  - TC-06: Wire format header correctness
  - TC-07: IV randomness (no reuse)
  - TC-08: Truncated input rejection
  - TC-09: Log message format validation
  - TC-10: EXT provider param parser
  - TC-11: Key hash file write and read
  - TC-12: Tampered key hash mismatch detection
- GitHub Actions CI: Ubuntu 24.04, NGINX 1.26.3 + 1.28.0

### Bug fixes (during development)
- Fixed "duplicate directive" error: moved `log_dir` default from
  `create_conf` to `init_conf` (ngx_conf_set_str_slot duplicate detection)
- Fixed double `#define` in version macro
- Fixed `config`: `-lcrypto -ldl` missing from static build `CORE_LIBS`
- Fixed `config`: `ngx_module_order` missing from static build branch
- Fixed Debian module path: `/usr/lib/nginx/modules/` symlink requirement

---

## Planned

### v1.1 (Phase 1 extension)
- Environment variable KMS support (Docker / Kubernetes secrets)
- Key integrity check in `securelog_aes_decrypt` tool
- Debian `.deb` / RPM package
- Integration tests (real nginx process)

### v2.0 (Phase 2)
- KMS Adapter Layer (HashiCorp Vault, AWS KMS, GCP KMS, Azure Key Vault)
- Envelope encryption (DEK per record, KEK in KMS)
- Automatic key rotation with graceful transition

### v2.1 (Enterprise / Commercial)
- D'Amo KMS Adapter
- PKCS#11 / HSM KMS Adapter
