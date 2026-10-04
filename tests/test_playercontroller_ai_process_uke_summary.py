#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_uke.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_UKE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FE6","0x002FA42C","2ca42f0000008100eb3a0a005c480000d43a","200001"
)
assert (m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(
    "fat","13300300c700000014110011",3,"0x11001114","07041286300211a7c408"
)
assert (m["code_size"],m["code_sha256"])==(199,"5a01db6954a400136e9050584744d4bedd5962586fa1d731211e9c0f313d9295")
assert m["locals"]==[
    {"index":0,"kind":"class","typedef_rid":396,"type":"AIParam","namespace":"","typedef_row_hex":"012010005b140000000000000903fa0c4110"},
    {"index":1,"kind":"primitive","type":"Boolean","element_type_raw":"0x02"},
    {"index":2,"kind":"valuetype","typedef_rid":2545,"type":"DamageLevelEnum_LMH","namespace":"","typedef_row_hex":"030100005e7900000000000045039a612d50"},
    {"index":3,"kind":"primitive","type":"Int32","element_type_raw":"0x08"}
]

assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
    ("0x0400614A","PlayerController_AI","PlObj"),
    ("0x04005FB3","Player","WresParam"),
    ("0x040010AA","WrestlerParam","aiParam"),
    ("0x04005FB7","Player","State"),
    ("0x04006118","PlayerController","padPush"),
    ("0x04005FBF","Player","HP"),
    ("0x04000D1D","AIParam","breakFall_LDmg"),
    ("0x04000D1E","AIParam","breakFall_MDmg"),
    ("0x04000D1F","AIParam","breakFall_HDmg"),
    ("0x04006117","PlayerController","padOn")
]
assert s["dll"]["normalized_field_access_map_sha256"]=="64b1da5a1b8d813d736515974bb69f061a6358651790a8b9bce917ce86dd8cc5"

assert [(x["call_il"],x["token"],x["canonical_fact"]) for x in s["dll"]["canonical_internal_calls"]]==[
    ("0x0075","0x06004F9B","FACT-0038"),
    ("0x00AA","0x06004955","FACT-0025")
]
assert s["dll"]["external_memberrefs"]==[]

assert [(x["il"],x["opcode"],x["target_il"]) for x in s["dll"]["branch_sites"]]==[
    ("0x0020","beq","0x0037"),
    ("0x0032","bne.un","0x003E"),
    ("0x0039","br","0x0063"),
    ("0x004B","bne.un","0x0063"),
    ("0x005C","brtrue","0x0063"),
    ("0x0064","brtrue","0x006A"),
    ("0x007E","brtrue","0x008F"),
    ("0x008A","br","0x00A9"),
    ("0x0091","bne.un","0x00A2"),
    ("0x009D","br","0x00A9"),
    ("0x00AF","brfalse","0x00C6")
]
assert s["dll"]["raw_write"]=={
    "field":"PlayerController.padOn","operation":"prior padOn OR raw 256",
    "read_il":"0x00B6","or_value_il":"0x00BB","write_il":"0x00C1"
}
assert s["dll"]["direct_in_assembly_references"]==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Update",
    "caller_token":"0x0600502B","caller_rva":"0x002FFC68","caller_code_size":984,
    "caller_code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9",
    "call_il":"0x03D2","opcode":"call"
}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="75d6657386ea1078b0385ae51f25352a4e249b8962945b55cb7c3c4d2e3cad78"
assert s["dll"]["normalized_caller_token_set_sha256"]=="8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63"

c=s["capture_boundary"]
assert c["playercontroller_ai_process_uke_row_count"]==0
assert c["playercontroller_ai_get_damage_level_lmh_row_count"]==0
assert c["matchmisc_rate100_check_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False

print("DLL PLAYERCONTROLLER AI PROCESS UKE SUMMARY: PASS")
