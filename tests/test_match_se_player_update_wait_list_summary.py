#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_se_player_update_wait_list.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_SE_PLAYER_UPDATE_WAIT_LIST_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600527A","0x00321744",51,"8bb4fe7bdd1afe7b8440b399d90daf4e90da035214a8732bbb3f105723cdafcf")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(23,3,0)
assert s["dll"]["field"]=={"name":"rfs_se_wait_list","token":"0x040086E5"}
assert s["dll"]["exact_loop"]["raw_index_range"]=={"min_inclusive":0,"max_inclusive":108}
assert s["dll"]["exact_loop"]["element_gate"]["condition"]=="rfs_se_wait_list[index] > 0"
assert s["dll"]["writer_bridge"]["fact_id"]=="FACT-0060"
assert s["dll"]["writer_bridge"]["raw_value"]==2
print("DLL MATCH SE PLAYER UPDATE WAIT LIST SUMMARY: PASS")
