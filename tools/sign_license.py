#!/usr/bin/env python3
"""
tools/sign_license.py
Maintainer offline tool for generating Ed25519 keypairs and minting signed commercial license tokens.
This tool is NOT packaged into releases and requires an offline private key.
"""
import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519
from hopzero.core.licensing import generate_license_key, verify_license_key, VALID_EDITIONS


def cmd_gen_key(args):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = pub.public_bytes_raw()

    out_priv = Path(args.out) if args.out else Path("license_private.key")
    out_priv.write_bytes(priv_bytes)
    print(f"Generated Ed25519 Private Key saved to: {out_priv}")
    print(f"Public Key (hex): {pub_bytes.hex()}")
    print(f"Public Key (b64): {base64.urlsafe_b64encode(pub_bytes).decode('ascii')}")


def cmd_sign(args):
    if not args.key_file and not os.getenv("HOPZERO_LICENSE_PRIVATE_KEY"):
        print("[FAIL] Missing private key file. Provide --key-file or set HOPZERO_LICENSE_PRIVATE_KEY.")
        sys.exit(1)

    if args.key_file:
        priv_bytes = Path(args.key_file).read_bytes()
    else:
        priv_val = os.getenv("HOPZERO_LICENSE_PRIVATE_KEY")
        priv_bytes = bytes.fromhex(priv_val) if len(priv_val) == 64 else base64.urlsafe_b64decode(priv_val + "==")

    features = [f.strip() for f in args.features.split(",") if f.strip()] if args.features else None

    token = generate_license_key(
        customer_id=args.customer,
        edition=args.edition,
        expires_at=args.expires,
        max_seats=args.seats,
        features=features,
        private_key=priv_bytes,
    )

    print("=" * 76)
    print("                 HOPZERO COMMERCIAL LICENSE TOKEN                     ")
    print("=" * 76)
    print(token)
    print("=" * 76)

    # Verification check with matching public key
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes_raw()
    info = verify_license_key(token, trusted_public_keys=[pub_bytes])
    print(f"Verification Check: valid={info.is_valid}, edition={info.edition}, expires={info.expires_at}")


def main():
    parser = argparse.ArgumentParser(description="HopZero Maintainer License Signing Tool")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    gen_p = subparsers.add_parser("gen-key", help="Generate a new Ed25519 license keypair")
    gen_p.add_argument("--out", "-o", help="Output private key path (default: license_private.key)")

    sign_p = subparsers.add_parser("sign", help="Mint a signed license token")
    sign_p.add_argument("--customer", "-c", required=True, help="Customer / Organization ID")
    sign_p.add_argument("--edition", "-e", required=True, choices=list(VALID_EDITIONS), help="Edition")
    sign_p.add_argument("--expires", "-x", required=True, help="Expiration date (ISO 8601, e.g. 2027-10-12T00:00:00Z)")
    sign_p.add_argument("--seats", "-s", type=int, default=5, help="Maximum seats")
    sign_p.add_argument("--features", "-f", help="Comma-separated feature list")
    sign_p.add_argument("--key-file", "-k", help="Path to offline Ed25519 private key")

    args = parser.parse_args()
    if args.cmd == "gen-key":
        cmd_gen_key(args)
    elif args.cmd == "sign":
        cmd_sign(args)


if __name__ == "__main__":
    main()
