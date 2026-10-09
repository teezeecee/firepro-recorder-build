#!/usr/bin/env python3
"""FACT-0264 stable source witness and registry checks."""
import hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_packed_loader_entry.summary.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["dll"]["method"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_PACKED_LOADER_ENTRY_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==("0x06005256","0x0031F250","50f2310000008100e55c0a005c480000ba3c","200001")
assert (m["code_size"],m["instruction_count"],w["dll"]["branch_count"])==(51,19,0)
assert len(bytes.fromhex(m["body_hex"]))==51
assert hashlib.sha256(bytes.fromhex(m["body_hex"])).hexdigest()==m["code_sha256"]=="e04ad14f86708279e782875a103814dcee242d1f0af8b01d8923a2197cbbe8d2"
assert m["body_hex"].startswith("72acce0070") and m["body_hex"].endswith("285a05000a07590d2a")
assert [(x["il"],x["operand"]) for x in w["dll"]["exact_token_sites"]]==[("0x0000","0x7000CEAC"),("0x0006","0x0A00055A"),("0x000D","0x0A0006DA"),("0x0012","0x010000E4"),("0x001A","0x0A00014F"),("0x001F","0x06005257"),("0x0025","0x0A0006DF"),("0x002A","0x0A00055A")]
assert w["dll"]["resource_string"]=={"token":"0x7000CEAC","value":"fprwaza"}
assert [x["name"] for x in w["dll"]["memberrefs"]]==["get_realtimeSinceStartup","Load","get_bytes","UnloadAsset"]
assert (w["dll"]["child"]["code_size"],w["dll"]["neighbor"]["code_size"])==(354,1735)
assert (R/"canonical/facts/FACT-0264-skill-data-man-packed-loader-entry.json").exists()
assert sum(x["fact_id"]=="FACT-0264" for x in reg["families"])==1
assert sum(x["family_id"]=="DLL_SKILL_DATA_MAN_PACKED_LOADER_ENTRY_V1" for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("SKILL DATA MAN PACKED LOADER ENTRY SUMMARY: PASS")
