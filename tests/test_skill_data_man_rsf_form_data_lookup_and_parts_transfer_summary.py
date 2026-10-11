"""FACT-0280 original DLL source-only static witness and registry gate."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_data_lookup_and_parts_transfer.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_DATA_LOOKUP_AND_PARTS_TRANSFER_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x04F1","0x0530",63,"6c0df9c5ae63c2d3e3ac6b1f0a94a6a97ff9eb0550b403be79df3451ae8dca90")
assert [len(bytes.fromhex(x["il_hex"])) for x in a["segments"]]==[17,18,28]
assert [x["name"] for x in a["segments"]]==["optional_skill_block_form_index","get_form_data_by_source_arguments","copy_two_source_fields_to_form_display"]
assert len(a["fields"])==6 and a["methoddef"]["token"]=="0x06001F17"
assert a["branch"]["branch_target_il"]=="0x0502" and a["branch"]["relative_s32"]==8
assert sum(x["fact_id"]=="FACT-0280" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0280-skill-data-man-rsf-form-data-lookup-parts-transfer.json").exists()
print("SKILL DATA MAN RSF FORM DATA LOOKUP AND PARTS TRANSFER SUMMARY: PASS")
