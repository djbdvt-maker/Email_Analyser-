# Cryptographic Key Management & Asymmetric Signing Architecture

This document outlines the asymmetric cryptographic architecture used for HopZero commercial licensing and release verification (F2).

---

## 1. Principles & Threat Model

1. **Asymmetric Public-Key Cryptography (Ed25519)**:
   - The application binary and source code contain **only the public keys** required for verification.
   - The private keys required for signing **remain offline** with the project maintainers and are never stored in repositories, distributed archives, CI pipelines, or host filesystems.
2. **Elimination of Symmetric HMAC Secrets**:
   - Earlier versions used symmetric HMAC signatures with environment variable fallbacks. Because symmetric schemes use the identical secret for both signing and verification, shipping or leaking a secret allows arbitrary forgery of licenses and releases.
   - HopZero v4.2.0 replaces all HMAC license and release signing mechanisms with Ed25519 digital signatures (`cryptography.hazmat.primitives.asymmetric.ed25519`).
3. **Honesty on Open-Source Licensing Protection**:
   - In an open-source or source-available application, client-side license checks can technically be modified or removed by anyone with access to the source code.
   - The embedded offline license verification is intended to assist honest enterprise customers with compliance tracking, edition validation, and entitlement management.
   - Legal protection derives from the Apache-2.0 / Commercial License Terms, support agreements, and enterprise-only components distributed separately.

---

## 2. Key Lifecycle & Operations

### 2.1 Key Generation
Maintainers generate keys offline using the maintainer utility:
```bash
# Generate license authority keypair
python tools/sign_license.py gen-key --out license_authority_2026.key

# Generate release signing keypair
python tools/sign_release.py gen-key --out release_authority_2026.key
```
The output displays the 32-byte public key (hex and base64), which is added to `OFFICIAL_LICENSE_PUBLIC_KEYS` or `OFFICIAL_RELEASE_PUBLIC_KEYS`.

### 2.2 Key Rotation & Multi-Key Trust
The application supports multiple embedded public keys in:
- `hopzero/core/licensing.py`: `OFFICIAL_LICENSE_PUBLIC_KEYS`
- `hopzero/core/signatures.py`: `OFFICIAL_RELEASE_PUBLIC_KEYS`

During verification, the application iterates over all trusted keys. To rotate a key:
1. Generate a new keypair for the upcoming period.
2. Append the new public key to the trusted public keys array in code.
3. Begin signing new licenses/releases with the new private key.
4. Existing licenses signed with the previous key continue to verify until expiration.

Enterprise air-gapped environments may inject additional trusted enterprise keys via the environment variable:
- `HOPZERO_TRUSTED_LICENSE_PUBLIC_KEYS`: comma-separated hex or base64 public keys.
- `HOPZERO_TRUSTED_RELEASE_PUBLIC_KEYS`: comma-separated hex or base64 public keys.

### 2.3 Migration from HMAC
All legacy HMAC licenses generated under earlier revisions (`HOPZERO_LICENSE_SECRET`) are superseded by Ed25519 versioned tokens (`v: 1`). Previous HMAC environment variables have been completely removed from configuration schemas and runtime code paths.
