"""FACT-0283 source-only original DLL bit-gated flags updates witness gate."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_flag_bit_or_updates.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_DATA_MAN_RSF_FORM_FLAG_BIT_OR_UPDATES_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x05A1","0x05FE",93,"c9c9f67cafdde8edf5443e35c6a54823ee42a7578715dfe019392ff90e8fd2b6")
assert [len(bytes.fromhex(x["il_hex"])) for x in a["segments"]]==[9,28,28,28]
assert [int(x["flags_or_mask"],16) for x in a["segments"][1:]]==[0x400,0x800,0x100]
assert [x["bit_mask"] for x in a["segments"][1:]]==[1,2,4]
assert [x["branch_target_il"] for x in a["segments"][1:]]==["0x05C6","0x05E2","0x05FE"]
assert a["field"]["token"]=="0x04007CE6" and a["field"]["metadata_row_hex"]=="0600314c010093370000"
assert sum(x["fact_id"]=="FACT-0283" for x in r["families"])==1
assert sum(x["family_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_FLAG_BIT_OR_UPDATES_V1" for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0283-skill-data-man-rsf-form-flag-bit-or-updates.json").exists()
print("SKILL DATA MAN RSF FORM FLAG BIT OR UPDATES SUMMARY: PASS")
