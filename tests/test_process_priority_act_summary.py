#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"process_priority_act.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_PRIORITY_ACT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x0600500A","0x002FD31C","200002",431,"0db6da9710767a5629dec05b3a7521e0aa1cb83f55d6332a648e89fa5917afc1")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(153,27,6)
assert m["local_types"]==["Player","AIParam","Int32","AIPriorityActEnum","DamageLevelEnum_LMH","Int32","Int32"]
g=s["dll"]["entry_gates"]
assert g[0]["condition"]=="currentPriAct == -1"
assert g[1]["raw_state_bypass"]==6 and g[1]["raw_state_limit"]==4
assert s["dll"]["priority_loop"]["raw_index_min"]==0 and s["dll"]["priority_loop"]["raw_index_max"]==11
assert s["dll"]["priority_loop"]["damage_level_split"]["raw_value"]==2
assert s["dll"]["priority_loop"]["mark_checked_before_rate_check"] is True
assert s["dll"]["priority_loop"]["rate_check_fact_id"]=="FACT-0025"
assert s["dll"]["action_tail"]["result_return_split"]==[
 {"condition":"result == 1","return":False},{"condition":"result > 0 and result != 1","return":True}]
c=s["dll"]["caller_bridge"]
assert (c["caller_token"],c["call_il"],c["post_call_il"],c["post_call_opcode"])==("0x0600502B","0x0208","0x020D","pop")
print("DLL PROCESS PRIORITY ACT SUMMARY: PASS")
