#!/usr/bin/env python3
"""
tools/sign_release.py
Maintainer offline tool for generating Ed25519 release signatures and signing release manifests.
This tool is NOT packaged into releases and requires an offline private key.
"""
import argparse
import base64
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519
from hopzero.core.signatures import compute_manifest_checksums, sign_manifest, verify_manifest_signature


def cmd_gen_key(args):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = pub.public_bytes_raw()

    out_priv = Path(args.out) if args.out else Path("release_private.key")
    out_priv.write_bytes(priv_bytes)
    print(f"Generated Ed25519 Release Private Key saved to: {out_priv}")
    print(f"Public Key (hex): {pub_bytes.hex()}")
    print(f"Public Key (b64): {base64.urlsafe_b64encode(pub_bytes).decode('ascii')}")


def cmd_sign(args):
    target_dir = Path(args.directory).resolve()
    if not target_dir.is_dir():
        print(f"[FAIL] Target directory does not exist: {target_dir}")
        sys.exit(1)

    if not args.key_file and not os.getenv("HOPZERO_RELEASE_PRIVATE_KEY"):
        print("[FAIL] Missing private key file. Provide --key-file or set HOPZERO_RELEASE_PRIVATE_KEY.")
        sys.exit(1)

    if args.key_file:
        priv_bytes = Path(args.key_file).read_bytes()
    else:
        priv_val = os.getenv("HOPZERO_RELEASE_PRIVATE_KEY")
        priv_bytes = bytes.fromhex(priv_val) if len(priv_val) == 64 else base64.urlsafe_b64decode(priv_val + "==")

    checksums = compute_manifest_checksums(target_dir)
    sig = sign_manifest(checksums, private_key=priv_bytes)

    manifest_file = target_dir / "release_manifest.json"
    sig_file = target_dir / "release_manifest.sig"

    manifest_file.write_text(json.dumps(checksums, indent=2, sort_keys=True), encoding="utf-8")
    sig_file.write_text(sig, encoding="utf-8")

    print(f"[OK] Signed {len(checksums)} files in {target_dir}")
    print(f"     Manifest: {manifest_file}")
    print(f"     Signature: {sig_file}")

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes_raw()
    valid = verify_manifest_signature(checksums, sig, trusted_public_keys=[pub_bytes])
    print(f"     Self-test verification: {valid}")


def main():
    parser = argparse.ArgumentParser(description="HopZero Maintainer Release Signing Tool")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    gen_p = subparsers.add_parser("gen-key", help="Generate a new Ed25519 release keypair")
    gen_p.add_argument("--out", "-o", help="Output private key path (default: release_private.key)")

    sign_p = subparsers.add_parser("sign", help="Sign release directory contents")
    sign_p.add_argument("--directory", "-d", required=True, help="Release directory to sign")
    sign_p.add_argument("--key-file", "-k", help="Path to offline Ed25519 private key")

    args = parser.parse_args()
    if args.cmd == "gen-key":
        cmd_gen_key(args)
    elif args.cmd == "sign":
        cmd_sign(args)


if __name__ == "__main__":
    main()
