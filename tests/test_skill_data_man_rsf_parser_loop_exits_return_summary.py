"""FACT-0286 original DLL-only parser-final-suffix witness and registry validation."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_parser_loop_exits_return.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_DATA_MAN_RSF_PARSER_LOOP_EXITS_RETURN_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x069E","0x06C7",41,"e05dd251bd3d06c3922c980ef2657ceb3265ebfcc76fb141a808533b9c2c837a")
assert [len(bytes.fromhex(z["il_hex"])) for z in a["segments"]]==[20,19,2]
assert b"".join(bytes.fromhex(z["il_hex"]) for z in a["segments"]).__len__()==41
assert [(a["segments"][i]["branch_il"],a["segments"][i]["branch_rel_s32"],a["segments"][i]["branch_target_il"]) for i in range(2)]==[("0x06AD",-551,"0x048B"),("0x06C0",-786,"0x03B3")]
assert (a["segments"][2]["il_hex"],a["return_local"],a["next_contiguous_il"])==("072a",1,None)
assert [a["fields"][f]["name"] for f in ["0x04007C93","0x04007C54"]]==["formNum","anmNum"]
assert a["method_code_end_il"]=="0x06C7"
assert a["complete_method_byte_coverage"]=={"start_il":"0x0000","end_exclusive_il":"0x06C7","full_il_sha256":m["code_sha256"]}
assert sum(z["fact_id"]=="FACT-0286" for z in r["families"])==1
assert sum(z["family_id"]=="DLL_SKILL_DATA_MAN_RSF_PARSER_LOOP_EXITS_RETURN_V1" for z in r["families"])==1
assert len({z["family_id"] for z in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0286-skill-data-man-rsf-parser-loop-exits-return.json").exists()
print("SKILL DATA MAN RSF PARSER LOOP EXITS RETURN SUMMARY: PASS")
