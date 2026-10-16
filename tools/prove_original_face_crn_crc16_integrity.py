#!/usr/bin/env python3
"""FACT-0373 original-byte Crunch CRC16 check. Run with original private vault source."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "canonical/witnesses/RESOBJECT-001/original_face_crn_crc16_integrity.summary.json"

def crn_crc16(data):
    crc = 0xFFFF
    for byte in data:
        q = byte ^ (crc >> 8)
        crc = (crc << 8) & 0xFFFF
        r = (q >> 4) ^ q
        crc ^= r
        r <<= 5
        crc ^= r
        r <<= 7
        crc ^= r
        crc &= 0xFFFF
    return (~crc) & 0xFFFF

def prove_original(texture_path, summary):
    original = Path(texture_path).read_bytes()
    src = summary["original_texture"]
    assert len(original) == src["original_bytes"]
    assert hashlib.sha256(original).hexdigest() == src["sha256"]
    bounds = summary["encoded_container"]
    encoded = original[bounds["object_offset"]:bounds["object_end_exclusive"]]
    assert len(encoded) == bounds["bytes"]
    assert crn_crc16(b"123456789") == 0xD64E
    result = {}
    for name in ("header", "data"):
        spec = summary["checks"][name]
        start, end = spec["encoded_span"]
        calc = crn_crc16(encoded[start:end])
        stored_start, stored_end = spec["stored_field_encoded_span"]
        stored = int.from_bytes(encoded[stored_start:stored_end], "big")
        expected = int(spec["calculated_hex"], 16)
        assert calc == expected == stored == int(spec["stored_hex"], 16), name + " CRC16"
        result[name] = f"{calc:04x}"
    return {"fact_id":"FACT-0373", "source_sha256":src["sha256"],"computed_crc16":result,"decoded_pixels":False,"runtime_eligible":False}

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--texture", required=True, help="Private original Texture2D PathID15464 .bin")
    x = p.parse_args()
    print(json.dumps(prove_original(x.texture, json.loads(SUMMARY.read_text(encoding="utf-8"))), sort_keys=True))
    print("FACT0373_ORIGINAL_SOURCE_CRN_CRC16_PASS")
