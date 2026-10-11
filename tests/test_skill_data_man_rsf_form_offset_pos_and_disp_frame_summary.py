"""FACT-0281 source-only original DLL witness and registry gate."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_offset_pos_and_disp_frame.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_OFFSET_POS_AND_DISP_FRAME_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x0530","0x0570",64,"c104bc32de801488e4bec4a92f56d4f948f6a1c258d82114f4bd04a98cc79158")
assert [len(bytes.fromhex(x["il_hex"])) for x in a["segments"]]==[10,10,30,14]
assert [x["name"] for x in a["segments"]]==["read_first_signed_form_offset_component","read_second_signed_form_offset_component","construct_scaled_vector2_assign_form_offset_position","read_unsigned_byte_assign_disp_frame"]
assert a["float_multiplier_ieee754_le_hex"]=="00000040"
assert (a["fields"]["0x04007CDB"]["name"],a["fields"]["0x04007CDC"]["name"])==("formOfsPos","dispFrm")
assert a["constructor_memberref"]["token"]=="0x0A000088"
assert sum(x["fact_id"]=="FACT-0281" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0281-skill-data-man-rsf-form-offset-pos-disp-frame.json").exists()
print("SKILL DATA MAN RSF FORM OFFSET POS AND DISP FRAME SUMMARY: PASS")
