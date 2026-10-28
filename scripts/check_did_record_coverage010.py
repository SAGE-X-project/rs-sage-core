#!/usr/bin/env python3
"""Enforce line coverage of each selected source file."""
import json
from pathlib import Path
import sys

FILES = (
    "src/didsource010.rs",
    "src/registry010/record_observer010.rs",
    "src/crypto/keys.rs",
    "src/crypto/p256.rs",
    "src/crypto/secp256k1.rs",
    "src/did/proof.rs",
    "src/formats/mod.rs",
    "src/registry010/web_record_proofs010.rs",
)

def main():
    report = json.loads(Path(sys.argv[1]).read_text())
    files = report["data"][0]["files"]
    for relative in FILES:
        matches = [f for f in files if f["filename"].replace("\\", "/").endswith("/" + relative)]
        if len(matches) != 1:
            raise SystemExit(f"missing or duplicate coverage: {relative}")
        lines = matches[0]["summary"]["lines"]
        if lines["count"] == 0 or lines["covered"] * 100 < lines["count"] * 90:
            raise SystemExit(f"{relative}: {lines['covered']}/{lines['count']} lines; 90% required")
        print(f"{relative}: {lines['covered']}/{lines['count']} lines ({lines['percent']:.2f}%)")

if __name__ == "__main__":
    main()
