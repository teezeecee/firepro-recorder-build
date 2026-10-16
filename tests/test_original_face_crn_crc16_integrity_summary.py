"""FACT-0373 summary-only gate. Original proprietary source checked with separate private verifier."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
s = json.loads((ROOT / "canonical/witnesses/RESOBJECT-001/original_face_crn_crc16_integrity.summary.json").read_text())
f = json.loads((ROOT / "canonical/facts/FACT-0373-original-face-crn-crc16-integrity.json").read_text())
reg = json.loads((ROOT / "canonical/transition_registry.json").read_text())
parent = json.loads((ROOT / "canonical/witnesses/RESOBJECT-001/original_face_texture2d_crn_container.summary.json").read_text())

spec = importlib.util.spec_from_file_location("proof", ROOT / "tools/prove_original_face_crn_crc16_integrity.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.crn_crc16(b"123456789") == 0xD64E
assert s["parent_fact"] == "FACT-0372" and s["source_ids"] == ["RESOBJECT-001"]
assert s["original_texture"]["sha256"] == parent["source_texture"]["sha256"]
assert s["encoded_container"]["bytes"] == parent["unity_fields"]["complete_image_size"] == 54497
assert s["encoded_container"]["object_offset"] == 80
assert s["private_witness"]["committed_to_public_git"] is False
assert s["decoded_pixels"] is False and s["runtime_eligible"] is False
assert f["fact_id"] == "FACT-0373" and f["status"] == "PROVEN_PACKED_DATA"
assert s["checks"]["header"]["encoded_span"] == [6,74]
assert s["checks"]["data"]["encoded_span"] == [74,54497]
assert s["checks"]["header"]["calculated_hex"] == s["checks"]["header"]["stored_hex"] == parent["crn_header"]["header_crc16_hex"]
assert s["checks"]["data"]["calculated_hex"] == s["checks"]["data"]["stored_hex"] == parent["crn_header"]["data_crc16_hex"]
assert len([x for x in reg["families"] if x["fact_id"] == "FACT-0373" and x["runtime_eligible"] is False]) == 1
assert reg["runtime_unlocked"] is False
print("FACT-0373 derived summary and CRC16 algorithm vector PASS (private source externally verified)")
