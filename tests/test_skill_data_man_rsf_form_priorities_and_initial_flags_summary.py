"""FACT-0282 original DLL source witness and registry static gate."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_priorities_and_initial_flags.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_PRIORITIES_AND_INITIAL_FLAGS_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x0570","0x05A1",49,"78bf425b69801c4c958d960905d88d7fd243294def1891207fc7883b6ac2ab66")
assert [len(bytes.fromhex(x["il_hex"])) for x in a["segments"]]==[9,13,13,14]
assert [x["name"] for x in a["segments"]]==["read_unsigned_source_priority_byte_to_local4","extract_form_priority_high_two_bits","extract_ring_priority_middle_three_bits","read_unsigned_source_byte_into_initial_flags"]
assert (a["form_priority"]["right_shift"],a["form_priority"]["and_mask"])==(6,3)
assert (a["ring_priority"]["right_shift"],a["ring_priority"]["and_mask"])==(3,7)
assert len(a["fields"])==3 and a["fields"]["0x04007CDE"]["signature_hex"]=="0611a9c8"
assert sum(x["fact_id"]=="FACT-0282" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0282-skill-data-man-rsf-form-priorities-and-initial-flags.json").exists()
print("SKILL DATA MAN RSF FORM PRIORITIES AND INITIAL FLAGS SUMMARY: PASS")
