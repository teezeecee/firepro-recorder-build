#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_drop_weapon.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_DROP_WEAPON_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06005022","0x002FF710","10f72f0000008100d73f0a00db490000de3a","200002"
)
assert (m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(
    "fat","133002006d00000069090011",2,"0x11000969","070112a838"
)
assert (m["code_size"],m["code_sha256"])==(109,"b7c63a31c3fd694f21dc16ae22caf91866d1eb98336000f37e5b763c71d672dd")
assert m["local_type"]["type"]=="Referee" and m["local_type"]["typedef_rid"]==2574

assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
    ("0x0400614A","PlayerController_AI","PlObj"),
    ("0x0400600B","Player","weaponIdx"),
    ("0x040062DC","RefereeMan","inst"),
    ("0x040062A4","Referee","TargetPlIdx"),
    ("0x04005FA6","Player","PlIdx"),
    ("0x0400629D","Referee","State"),
    ("0x040062CC","Referee","RefeCount"),
    ("0x04006118","PlayerController","padPush")
]
assert s["dll"]["normalized_field_access_map_sha256"]=="ca0ae7487f9d008d649907116730fbd536f7bed894c97ed14f785e06f8eb6fb2"

calls=s["dll"]["canonical_internal_calls"]
assert calls==[{
    "call_il":"0x0018","opcode":"callvirt","token":"0x060050B6",
    "method":"RefereeMan.GetRefereeObj","canonical_fact":"FACT-0065",
    "callee_code_size":9,
    "callee_code_sha256":"aa2a417db5ba1940541d91f5a98fe26ec59230af147fdb4dd2e768ca0dad1e4d"
}]
ext=s["dll"]["external_memberrefs"]
assert len(ext)==1
assert (ext[0]["call_il"],ext[0]["token"],ext[0]["owner"],ext[0]["method"],ext[0]["signature_blob_hex"])==(
    "0x001F","0x0A00002A","UnityEngine.Object","op_Implicit","0001021269"
)

assert [(x["il"],x["opcode"],x["target_il"]) for x in s["dll"]["branch_sites"]]==[
    ("0x000C","bge","0x0013"),
    ("0x0024","brtrue","0x002B"),
    ("0x003C","beq","0x0043"),
    ("0x004B","beq","0x0052"),
    ("0x0059","bge","0x0060")
]
assert s["dll"]["raw_writes"]==[{"field":"PlayerController.padPush","raw_value":128,"value_il":"0x0061","write_il":"0x0066"}]
assert [x["raw_boolean"] for x in s["dll"]["return_sites"]]==[False,False,False,False,False,True]

assert s["dll"]["direct_in_assembly_references"]==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Update",
    "caller_token":"0x0600502B","caller_rva":"0x002FFC68","caller_code_size":984,
    "caller_code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9",
    "call_il":"0x01B5","opcode":"call"
}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="44fe025ddce4ea8911d33dbcb9a21828339ec328f0f8917b0fc631c39b6f54f6"
assert s["dll"]["normalized_caller_token_set_sha256"]=="8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63"

c=s["capture_boundary"]
assert c["playercontroller_ai_process_drop_weapon_row_count"]==0
assert c["refereeman_get_referee_obj_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False

print("DLL PLAYERCONTROLLER AI PROCESS DROP WEAPON SUMMARY: PASS")
