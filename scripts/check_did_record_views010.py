#!/usr/bin/env python3
"""Compare two separate local fixture processes with independently authored views.

No endpoints, private keys, transaction paths or protected operations are used.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/did-record-projections010.json"
PIN = "06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b"

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result

def reject_constant(value):
    raise ValueError(f"non-JSON numeric constant: {value}")

def strict_json(data):
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)

def exact_json(value):
    # Text comparison keeps boolean, number, string and array types distinct.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

def main():
    data = FIXTURE.read_bytes()
    fixture = strict_json(data)
    assert fixture["basis"] == PIN, "fixture basis changed"
    cases = fixture["cases"]
    expected = {case["name"]: case["expected"] for case in cases}
    assert len(expected) == len(cases) == 12, "missing or duplicate cases"
    # Do not feed oracle fields to either process.
    source = json.dumps({"cases": [{"name": c["name"], "record": c["record"]} for c in cases]}).encode()
    subprocess.run(["cargo", "build", "--locked", "--example", "did_record_view010"], cwd=ROOT, check=True, timeout=300)
    rust = ROOT / "target/debug/examples/did_record_view010"
    with tempfile.TemporaryDirectory(prefix="sage-did-reference-") as temp:
        go_binary = str(Path(temp) / "reference")
        subprocess.run([os.environ.get("SAGE_TEST_GO", "go"), "build", "-mod=readonly", "-o", go_binary, "."], cwd=ROOT / "tests/go-did-reference", check=True, timeout=300)
        for name, binary in [("Rust", str(rust)), ("Go", go_binary)]:
            result = subprocess.run([binary], input=source, capture_output=True, check=True, timeout=30)
            actual = strict_json(result.stdout)
            assert actual.keys() == expected.keys(), f"{name}: case set differs"
            for case in expected:
                for projection in ("core10", "did11"):
                    view = actual[case][projection]
                    # Go's producer keeps struct member order. Compare complete
                    # parsed content after deterministic ASCII-only formatting;
                    # arrays and every member remain exact, none are filtered.
                    parsed = strict_json(view["document"])
                    view["document"] = exact_json(parsed)
                assert exact_json(actual[case]) == exact_json(expected[case]), f"{name}: {case} differs from independent expected views"
            print(f"{name}: 12 records, 24 views, complete document content and typed metadata match")
    print("PASS: fixture-only comparison; deployed readiness NOT_RUN; authorization NOT_GRANTED")

if __name__ == "__main__":
    main()
