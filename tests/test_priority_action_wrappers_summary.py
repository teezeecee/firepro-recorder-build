#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"priority_action_wrappers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PRIORITY_ACTION_WRAPPERS_V1"
m=s["dll"]["methods"]
assert len(m)==7
want={
"SetAIAct_DownAtk":("0x06004FA4",30,"fb38a89d3118cf815885af4d76af0a9a8a2c4744c5d9352a6f58cca215640589",13,1,1),
"SetAIAct_RunUpDive_Stand":("0x06004FA2",21,"94e61e33b42bff7c649e3d687172f74aa95a6083618dc9fa82e1e3c1e6fdd431",8,0,1),
"SetAIAct_RunUpDive_Down":("0x06004FA3",21,"fc342bf4ac6481bbab368979011af8b3a878a91e00528b03d11c7f8021ce0b81",8,0,1),
"SetAIAct_CornerDive":("0x06004FA1",34,"76067b8223899419015727846653c64dcf88f7aba379d6621dac196ef2bcb802",14,0,1),
"SetAIAct_PriAct_RunAtk":("0x06004FAA",17,"09d1a53cf821b1ed7cf1f66622e3b14e1cfd5d8d86b4de366aaba3387e8ad46f",8,0,1),
"SetAIAct_GoGrapple":("0x06004F9E",23,"978e82da32179445718786287df804ca334ac6f1889e726bec8774e5a13ccf12",11,0,1),
"SetAIAct_GoBackGrapple":("0x06004FA0",16,"78b1f889deb727931a2cf293d6125dbba940b2f77b8d67e400fa8c99cdf195ac",8,0,1)}
for x in m:
 w=want[x["method"]]
 assert (x["token"],x["code_size"],x["code_sha256"],x["instruction_count"],x["branch_instruction_count"],x["call_instruction_count"])==w
assert s["dll"]["set_ai_act_core"]["status"]=="OUTSIDE_FACT"
assert [x["set_ai_act_args"][0] for x in s["dll"]["exact_wrappers"]]==[19,9,10,5,16,1,3]
assert [x["il"] for x in s["dll"]["fact_0040_bridge"]["calls"]]==["0x00BF","0x00E0","0x012F","0x013C","0x01AE","0x01F3","0x022C","0x024B"]
print("DLL PRIORITY ACTION WRAPPERS SUMMARY: PASS")
