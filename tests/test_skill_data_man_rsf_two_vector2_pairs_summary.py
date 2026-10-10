#!/usr/bin/env python3
"""FACT-0271 witness + registry; independent verifier replays original DLL."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_two_vector2_pairs.summary.json").read_text())
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["method"];v=d["window"];a=v["first_pair"];b=v["second_pair"];mr=v["constructor_memberref"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_TWO_VECTOR2_SIGNED_UNSIGNED_PAIRS_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (v["start_il"],v["end_exclusive_il"],v["length_bytes"],v["source_sha256"])==("0x029E","0x02DE",64,"c5c8e2fff96546327060efe70884e00eba75821c32a9172df69d3551b4d0948c")
assert len(bytes.fromhex(a["source_hex"]))==33 and len(bytes.fromhex(b["source_hex"]))==31
assert a["relative_input_bytes"]==[36,37] and b["relative_input_bytes"]==[38,39]
assert a["per_byte_conversion"]=="ldelem.u1; conv.i1" and b["per_byte_conversion"]=="ldelem.u1"
assert (a["result_local"],b["result_local"])==(7,10)
assert (a["constructor_call_il"],b["constructor_call_il"])==("0x02BA","0x02D9")
assert mr["token"]=="0x0A000088" and (mr["type_name"],mr["type_namespace"])==("Vector2","UnityEngine")
assert mr["type_ref_row_id"]==12 and mr["signature_hex"]=="2002010c0c"
assert sum(x["fact_id"]=="FACT-0271" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (ROOT/"canonical/facts/FACT-0271-skill-data-man-rsf-two-vector2-pairs.json").exists()
print("SKILL DATA MAN RSF TWO VECTOR2 PAIRS SUMMARY: PASS")
