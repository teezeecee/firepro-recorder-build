#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"comleveldatamanager_get_com_level_data.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_COMLEVELDATAMANAGER_GET_COM_LEVEL_DATA_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06001049","0x00061357","57130600000086003f780800699701001d0c","200112863408"
)
assert m["parameters"]==[{
    "sequence":1,"name":"lv","metadata_type":"Int32",
    "param_row_hex":"00000100e9850100","flags_raw":"0x0000"
}]
assert m["return_type"]=={
    "kind":"class","typedef_rid":397,"type":"COMLevelData","namespace":"",
    "typedef_row_hex":"0100100063140000000000000903310d4410"
}
assert (m["header_format"],m["tiny_header_hex"],m["max_stack_implicit"],m["local_signature_token"])==(
    "tiny","26",8,"0x00000000"
)
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    9,"c78e8c870f4c865dfd55914f2c66fdca2c3d729088260483ece8ec917996123d","027b390d0004039a2a"
)
assert s["dll"]["fields"]==[{
    "token":"0x04000D39","owner":"COMLevelDataManager","name":"comLevelData",
    "field_row_hex":"0100483e0100820a0000","signature_blob_hex":"061d128634",
    "metadata_type":"COMLevelData[]"
}]
assert s["dll"]["field_accesses"]==[{"il":"0x0001","opcode":"ldfld","token":"0x04000D39"}]
assert s["dll"]["normalized_field_access_map_sha256"]=="9224c351b8ac43b7cbe994bfa4df3363ca01e644911b62a0127ef74798e35d4c"
assert s["dll"]["canonical_internal_calls"]==[]
assert s["dll"]["external_memberrefs"]==[]
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06004FD3","IsHappenPowerCompetition","0x0016","callvirt"),
    ("0x06004FD4","MakeRapidPushTbl","0x0032","callvirt"),
    ("0x06004FE4","Process_Grapple","0x0064","callvirt"),
    ("0x06005028","Check_FoxSleep","0x0076","callvirt")
]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(4,4)
assert s["dll"]["normalized_reference_map_sha256"]=="13d6ab1931848d868c91a13dfdf800e3a6d27355281f8a74741e51aef1a70c79"
assert s["dll"]["normalized_caller_token_set_sha256"]=="ffa09db9952975b9f41544ea8e0e0ad4319ea6d6b01fa032029225255aa37a83"
c=s["capture_boundary"]
assert c["comleveldatamanager_get_com_level_data_row_count"]==0
assert c["playercontroller_ai_is_happen_power_competition_row_count"]==0
assert c["playercontroller_ai_make_rapid_push_tbl_row_count"]==0
assert c["playercontroller_ai_process_grapple_row_count"]==0
assert c["playercontroller_ai_check_fox_sleep_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL COMLEVELDATAMANAGER GET COM LEVEL DATA SUMMARY: PASS")
