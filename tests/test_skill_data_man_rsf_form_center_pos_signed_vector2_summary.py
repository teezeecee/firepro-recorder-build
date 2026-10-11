"""FACT-0278 source-only static witness and registry gate."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_center_pos_signed_vector2.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_CENTER_POS_SIGNED_VECTOR2_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x04A6","0x04CC",38,"ef544099c322e46d4aee931555bad28a1b6beffb1f8a75be14f74efd7361997c")
assert [len(bytes.fromhex(x["il_hex"])) for x in a["segments"]]==[10,10,18]
assert [x["name"] for x in a["segments"]]==["read_x_unsigned_then_signed_to_local5","read_y_unsigned_then_signed_to_local6","construct_Vector2_and_store_centerPos"]
assert (a["cursor_local"],a["form_entry_local"],a["signed_x_local"],a["signed_y_local"])==(2,16,5,6)
assert (a["field"]["token"],a["field"]["name"])==("0x04007CD8","centerPos")
assert (a["vector2_typeref"]["token"],a["vector2_typeref"]["name"])==("0x0100000C","Vector2")
assert (a["constructor_memberref"]["token"],a["constructor_memberref"]["signature_hex"])==("0x0A000088","2002010c0c")
assert sum(x["fact_id"]=="FACT-0278" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0278-skill-data-man-rsf-form-center-pos-signed-vector2.json").exists()
print("SKILL DATA MAN RSF FORM CENTER POS SIGNED VECTOR2 SUMMARY: PASS")
