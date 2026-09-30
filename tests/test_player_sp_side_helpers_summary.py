#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_sp_side_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_SP_SIDE_HELPERS_V1"
ms={m["name"]:m for m in s["dll"]["methods"]}
assert (ms["ConsumeSP"]["code_size"],ms["ConsumeSP"]["code_sha256"])==(51,"0319a9b9582c72089b9455369fa000ad2d7713ad775bcb2eb0836f21c773d243")
assert (ms["RecoverSP"]["code_size"],ms["RecoverSP"]["code_sha256"])==(100,"9879da28f6a20f4435ae4bb27ba85d7f920ce913279bdfd0a7df12ecfc797ddf")
assert (ms["InvokeUkeBonus"]["code_size"],ms["InvokeUkeBonus"]["code_sha256"])==(144,"70c0105528475fabfc6a645f2b42355b7a3063334b6ee9abe25c09f00fa6e334")
assert s["dll"]["consume_sp"]["gate_sequence"]==["MatchMain.inst converts true","MatchMain.isTimeCounting != 0","MatchMain.isMatchEnd == 0"]
assert s["dll"]["recover_sp"]["heal_table_field_token"]=="0x04006082"
assert s["dll"]["invoke_uke_bonus"]["raw_thresholds"]==[7680,15360,30720]
assert s["dll"]["invoke_uke_bonus"]["comparison_opcode"]=="ble" and s["dll"]["invoke_uke_bonus"]["increment_each"]==1800
assert [x["fact_id"] for x in s["caller_bridges"][:2]]==["FACT-0018","FACT-0020"]
assert s["caller_bridges"][2]["fact_id"]=="FACT-0027"
print("DLL PLAYER SP SIDE HELPERS SUMMARY: PASS")
