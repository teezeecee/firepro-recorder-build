#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weaponman_get_inst.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPONMAN_GET_INST_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006AC0","0x00435282","000012b510")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("tiny",6,"8efdce8690337e223d2f0de688a62b433f4d6515c73fa84c203aadbca4f524fb")
assert m["body_hex"]=="7eeab600042a"
f=s["dll"]["field"]
assert (f["token"],f["owner"],f["name"],f["signature_blob_hex"])==("0x0400B6EA","WeaponMan","inst","0612b510")
assert s["dll"]["direct_reference_count"]==8
assert s["dll"]["direct_caller_method_count"]==6
assert len(s["dll"]["direct_in_assembly_references"])==8
canon={(x.get("canonical_fact"),x["caller_type"],x["caller_method"],x["call_il"]) for x in s["dll"]["direct_in_assembly_references"] if x.get("canonical_fact")}
assert canon=={
 ("FACT-0015","FormAnimator","PlayAnimationSE","0x0098"),
 ("FACT-0196","Weapon","SetPattern","0x0015")
}
c=s["capture_boundary"]
assert c["weaponman_get_inst_row_count"]==0
assert c["formanimator_play_animation_se_execution_count"]==45458
assert c["promoted_as_evidence"] is False
print("DLL WEAPONMAN GET INST SUMMARY: PASS")
