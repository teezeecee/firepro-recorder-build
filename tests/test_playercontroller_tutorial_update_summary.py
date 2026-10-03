#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_tutorial_update.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_TUTORIAL_UPDATE_V1"
assert s["dll"]["base_type"]=={
    "type":"PlayerController","typedef_rid":2542,
    "update_method_token":"0x06004F97","canonical_fact":"FACT-0206"
}
sub=s["dll"]["subtype"]
assert (sub["type"],sub["typedef_rid"],sub["typedef_row_hex"],sub["extends_typedeforref_raw"],sub["extends_rid"])==(
    "PlayerController_Tutorial",2560,"010010006b7a000000000000b827c8613b50","0x27B8",2542
)
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x0600503D","0x00300794","940730000000c600edc800005c480000ed3a","200001"
)
assert (m["method_attributes_raw"],m["newslot_bit_set"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==(
    "0x00C6",False,"fat","133003006001000000000000",3,"0x00000000"
)
assert (m["code_size"],m["code_sha256"])==(352,"ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe")
assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
    ("0x04006117","PlayerController","padOn"),
    ("0x04006118","PlayerController","padPush"),
    ("0x040061C8","PlayerController_Tutorial","plObj"),
    ("0x04005FEE","Player","Zone"),
    ("0x04005FAA","Player","PlPos"),
    ("0x040061CA","PlayerController_Tutorial","HomePos"),
    ("0x04006049","Player","isPinfallDef"),
    ("0x0400604C","Player","isSubmissionDef")
]
assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["member_fields"]]==[
    ("0x0A000009","UnityEngine.Vector3","x"),
    ("0x0A00000A","UnityEngine.Vector3","y"),
    ("0x0A000059","UnityEngine.Vector2","x"),
    ("0x0A00005A","UnityEngine.Vector2","y")
]
assert s["dll"]["normalized_field_access_map_sha256"]=="c4011f423dd22a5bd5030ec5d1d0ac332605ed8ecbd5d25b186d00d3bc58f045"
assert [(x["call_il"],x["opcode"],x["token"],x["canonical_fact"]) for x in s["dll"]["canonical_internal_calls"]]==[
    ("0x0025","callvirt","0x06004F74","FACT-0225"),
    ("0x0035","callvirt","0x06004F75","FACT-0223"),
    ("0x010B","call","0x0600503C","FACT-0226"),
    ("0x0122","call","0x06004955","FACT-0025"),
    ("0x014E","call","0x06004955","FACT-0025")
]
assert s["dll"]["direct_in_assembly_references"]==[]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(0,0)
assert s["dll"]["normalized_reference_map_sha256"]=="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
assert s["dll"]["normalized_caller_token_set_sha256"]=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
assert s["dll"]["remaining_open_override_frontier"]==[{
    "type":"PlayerController_AI","token":"0x0600502B","rva":"0x002FFC68",
    "code_size":984,"code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9"
}]
c=s["capture_boundary"]
assert all(c[k]==0 for k in (
    "playercontroller_tutorial_update_row_count",
    "playercontroller_tutorial_process_grapple_row_count",
    "player_start_force_control_row_count",
    "player_end_force_control_row_count",
    "matchmisc_rate100_check_row_count",
    "playercontroller_ai_update_row_count"
))
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER TUTORIAL UPDATE SUMMARY: PASS")
