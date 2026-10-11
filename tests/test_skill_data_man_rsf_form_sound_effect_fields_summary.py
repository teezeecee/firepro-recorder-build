"""FACT-0285 exact source-only witness/registry static assertions."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_sound_effect_fields.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_DATA_MAN_RSF_FORM_SOUND_EFFECT_FIELDS_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x0641","0x069E",93,"9676632c4efd1721c279ace3496f80d84e077f0cf4b1e06a430ff3def3248765")
assert [len(bytes.fromhex(z["il_hex"])) for z in a["segments"]]==[9,29,13,9,12,13,8]
assert b"".join(bytes.fromhex(z["il_hex"]) for z in a["segments"]).__len__()==93
assert a["segments"][0]["il_hex"]==a["segments"][3]["il_hex"]=="03082517580c911304"
assert (a["flags_branch_il"],a["flags_branch_target_il"],a["flags_branch_rel_s32"])==("0x064F","0x0667",19)
assert (a["cursor_local"],a["cursor_advances"],a["source_byte_local"])==(2,2,4)
assert [a["fields"][f"0x04007CE{i:X}"]["name"] for i in range(2,7)]==["seID","seLevel","effectID","ringVibration","flags"]
assert a["next_contiguous_il"]=="0x069E"
assert sum(z["fact_id"]=="FACT-0285" for z in r["families"])==1
assert sum(z["family_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_SOUND_EFFECT_FIELDS_V1" for z in r["families"])==1
assert len({z["family_id"] for z in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0285-skill-data-man-rsf-form-sound-effect-fields.json").exists()
print("SKILL DATA MAN RSF FORM SOUND EFFECT FIELDS SUMMARY: PASS")
