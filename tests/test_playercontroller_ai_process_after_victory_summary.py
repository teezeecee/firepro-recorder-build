#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_after_victory.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_AFTER_VICTORY_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06005020","0x002FF53C","3cf52f0000008100ac3f0a00db490000de3a","200002"
)
assert (m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(
    "fat","13300200770000003f110011",2,"0x1100113F","070111a39c"
)
assert (m["code_size"],m["code_sha256"])==(119,"5334c091183b118519531eb8a6518584bff6b89ddf64bb343899315321cd59dc")
assert (m["local_type"]["type"],m["local_type"]["typedef_rid"],m["local_type"]["typedef_row_hex"])==(
    "ResultPosition",2279,"01010000da6a0000000000004503ad56d048"
)

assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
    ("0x04006166","PlayerController_AI","doneVictoryPerformance"),
    ("0x0400576C","MatchMain","inst"),
    ("0x04005753","MatchMain","isMatchEnd"),
    ("0x0400614A","PlayerController_AI","PlObj"),
    ("0x04005FB7","Player","State"),
    ("0x040056FF","MatchEvaluation","inst"),
    ("0x04005700","MatchEvaluation","PlResult"),
    ("0x04005FA6","Player","PlIdx"),
    ("0x040056CF","PlayerMatchResult","resultPosition"),
    ("0x04006118","PlayerController","padPush"),
    ("0x04006117","PlayerController","padOn")
]
assert s["dll"]["normalized_field_access_map_sha256"]=="d15eb9ead3cef5447ef970087f12de574c66c52c8b64285d8e2b51311962c92f"
assert s["dll"]["canonical_internal_calls"]==[]
assert s["dll"]["external_memberrefs"]==[]

assert [(x["il"],x["opcode"],x["target_il"]) for x in s["dll"]["branch_sites"]]==[
    ("0x0006","brfalse","0x000D"),
    ("0x0017","brtrue","0x001E"),
    ("0x002A","ble","0x0031"),
    ("0x004E","brfalse","0x005A"),
    ("0x0055","bne.un","0x0075")
]
assert s["dll"]["raw_writes"]==[
    {"field":"PlayerController.padPush","raw_value":16384,"value_il":"0x005B","write_il":"0x0060"},
    {"field":"PlayerController.padOn","raw_value":0,"value_il":"0x0066","write_il":"0x0067"},
    {"field":"PlayerController_AI.doneVictoryPerformance","raw_value":True,"value_il":"0x006D","write_il":"0x006E"}
]
assert [x["raw_boolean"] for x in s["dll"]["return_sites"]]==[False,False,False,True,False]

assert s["dll"]["direct_in_assembly_references"]==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Update",
    "caller_token":"0x0600502B","caller_rva":"0x002FFC68","caller_code_size":984,
    "caller_code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9",
    "call_il":"0x028C","opcode":"call"
}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="2cca62a08c4daa6d8de2163b0d991ec736ecc55decd5e89746b5859603cc0dc2"
assert s["dll"]["normalized_caller_token_set_sha256"]=="8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63"

c=s["capture_boundary"]
assert c["playercontroller_ai_process_after_victory_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False

print("DLL PLAYERCONTROLLER AI PROCESS AFTER VICTORY SUMMARY: PASS")
