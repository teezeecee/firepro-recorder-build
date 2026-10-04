#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_end_fall_submission_won.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_END_FALL_SUBMISSION_WON_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06005025","0x002FF870","70f82f000000810013400a00db490000de3a","200002"
)
assert (m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(
    "fat","13300300b4000000980c0011",3,"0x11000C98","070212a78808"
)
assert (m["code_size"],m["code_sha256"])==(180,"e43bed886326ec138725263c219956e6246d4a71aaaf3553d40b7c16ed2b7b89")
assert m["locals"]==[
    {"index":0,"kind":"class","typedef_rid":2530,"type":"Player","namespace":"","typedef_row_hex":"01001000fd480000000000005500565fa74e"},
    {"index":1,"kind":"primitive","type":"Int32","element_type_raw":"0x08"}
]

assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
    ("0x040061FA","PlayerMan","inst"),
    ("0x0400614A","PlayerController_AI","PlObj"),
    ("0x04005FB1","Player","TargetPlIdx"),
    ("0x04006048","Player","isPinfallAtk"),
    ("0x0400604B","Player","isSubmissionAtk"),
    ("0x04006052","Player","isLose"),
    ("0x04006047","Player","isKO"),
    ("0x04006172","PlayerController_AI","endFallTimer"),
    ("0x04006118","PlayerController","padPush")
]
assert s["dll"]["normalized_field_access_map_sha256"]=="16ca98963995d1904ac34e07dc8b14f1d465aa79853589378e9bef4efec59722"

assert s["dll"]["canonical_internal_calls"]==[{
    "call_il":"0x0010","opcode":"callvirt","token":"0x06005065",
    "method":"PlayerMan.GetPlObj","canonical_fact":"FACT-0109",
    "callee_code_size":25,
    "callee_code_sha256":"32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8"
}]
ext=s["dll"]["external_memberrefs"]
assert len(ext)==1
assert (ext[0]["call_il"],ext[0]["token"],ext[0]["owner"],ext[0]["method"],ext[0]["signature_blob_hex"])==(
    "0x0017","0x0A00002A","UnityEngine.Object","op_Implicit","0001021269"
)

assert [(x["il"],x["opcode"],x["target_il"]) for x in s["dll"]["branch_sites"]]==[
    ("0x001C","brtrue","0x0023"),
    ("0x002E","brtrue","0x0043"),
    ("0x003E","brfalse","0x00AB"),
    ("0x0049","brtrue","0x0059"),
    ("0x0054","brfalse","0x009F"),
    ("0x0060","bge","0x0072"),
    ("0x006D","br","0x009A"),
    ("0x0084","bgt","0x009A"),
    ("0x009A","br","0x00A6"),
    ("0x00A6","br","0x00B2")
]
assert [x["raw_boolean"] for x in s["dll"]["return_sites"]]==[False,True,False]

refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06005021","Process_AfterMatchEnd","0x003E","call"),
    ("0x0600502B","Update","0x00AE","call")
]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(2,2)
assert s["dll"]["normalized_reference_map_sha256"]=="2071fc6d9b8540f9a1bbbef6ce5c63b0f0718d2f3224e1038a1ab22ea170ee9f"
assert s["dll"]["normalized_caller_token_set_sha256"]=="af1a57e5dc72e932feaa7fcf00d969af285afd85d7d99e51151c90bf00511fa8"

c=s["capture_boundary"]
assert c["playercontroller_ai_end_fall_submission_won_row_count"]==0
assert c["playerman_get_pl_obj_row_count"]==0
assert c["playercontroller_ai_process_after_match_end_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False

print("DLL PLAYERCONTROLLER AI END FALL SUBMISSION WON SUMMARY: PASS")
