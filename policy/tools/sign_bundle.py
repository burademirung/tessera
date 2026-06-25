#!/usr/bin/env python3
"""Build + sign a runtime policy bundle (reference impl; Phase-5 Go PA mirrors this).

Usage: sign_bundle.py <revision> <out_bundle.json> <out_sig.bin> <ed25519_seed_hex>
"""
import hashlib
import json
import sys
from pathlib import Path

from nacl.signing import SigningKey  # pip install pynacl

POLICY_DIR = Path(__file__).resolve().parents[1] / "authz"
# NOTE: data documents live alongside the .rego sources in authz/ (not a data/
# subdir), because OPA's dir-loading prefixes subdirectories into the data path.
DATA_FILES = ["rbac_data.json", "abac_data.json", "sod_data.json"]
REGO_FILES = ["main.rego", "rbac.rego", "abac.rego", "sod.rego"]


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    revision, out_bundle, out_sig, seed_hex = sys.argv[1:5]
    policies = {}
    hashes = {}
    for name in REGO_FILES:
        src = (POLICY_DIR / name).read_bytes()
        policies[name] = src.decode("utf-8")
        hashes[name] = sha256_hex(src)

    data = {}
    for rel in DATA_FILES:
        doc = json.loads((POLICY_DIR / rel).read_text())
        data.update(doc)
    data_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    data_hash = sha256_hex(data_bytes)

    manifest = {
        "version": "1",
        "revision": revision,
        "policies": policies,
        "data": data,
        "hashes": hashes,
        "data_hash": data_hash,
    }
    Path(out_bundle).write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))

    # Sign over a stable digest of (revision || sorted hashes || data_hash).
    signing_payload = json.dumps(
        {"revision": revision, "hashes": hashes, "data_hash": data_hash},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(signing_payload).digest()
    sig = SigningKey(bytes.fromhex(seed_hex)).sign(digest).signature
    Path(out_sig).write_bytes(sig)
    print(f"signed bundle revision={revision} data_hash={data_hash[:12]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
