"""FACT-0284 source-only witness and canonical registry static validation."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_direction_bits_and_altitude.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_DATA_MAN_RSF_FORM_DIRECTION_BITS_AND_ALTITUDE_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x05FE","0x0641",67,"9fa1cfe167f8cf98d33726a5e246fc22c9501001df4bed430a1205d512501916")
assert [len(bytes.fromhex(z["il_hex"])) for z in a["segments"]]==[8,17,8,21,13]
assert [z["name"] for z in a["segments"]]==["initialize_dir_LR_zero","conditionally_assign_dir_LR_one_if_bit8","initialize_dir_UD_zero","conditionally_assign_dir_UD_one_if_bit128","assign_altitude_three_bits"]
assert (a["segments"][1]["bit_mask"],a["segments"][3]["bit_mask"])==(8,128)
assert (a["segments"][1]["branch_target_il"],a["segments"][3]["branch_target_il"])==("0x0617","0x0634")
assert (a["segments"][4]["right_shift"],a["segments"][4]["and_mask"])==(4,7)
assert [a["fields"][z]["name"] for z in ["0x04007CDF","0x04007CE0","0x04007CE1"]]==["dir_LR","dir_UD","altitude"]
assert a["cursor_modified_in_window"] is False
assert sum(z["fact_id"]=="FACT-0284" for z in r["families"])==1
assert sum(z["family_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_DIRECTION_BITS_AND_ALTITUDE_V1" for z in r["families"])==1
assert len({z["family_id"] for z in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0284-skill-data-man-rsf-form-direction-bits-and-altitude.json").exists()
print("SKILL DATA MAN RSF FORM DIRECTION BITS AND ALTITUDE SUMMARY: PASS")
