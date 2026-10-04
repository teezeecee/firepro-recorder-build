#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_make_rapid_push_tbl.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_MAKE_RAPID_PUSH_TBL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FD4","0x002F8DC4","c48d2f000000860097390a005c480000c93a","200001"
)
assert m["parameters"]==[]
assert m["return_type"]=={"metadata_type":"Void"}
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0086","fat","133004003401000007110011",4,"0x11001107"
)
assert (m["code_size"],m["code_sha256"])==(
    308,"63b284583be3198f0647d16649fe43126b7f5c5d0b0c6a5c2ba73ad233530db7"
)
assert m["body_hex"]=="160a380d000000027b6361000406169c0617580a061f3c3febffffff7ed12a00047bd22a00040b7e380d0004077bd65700046f491000060c02087b330d0004087b340d00041758287b4900067d62610004027b62610004163d0800000002167d626100042a027b626100041f3c3e08000000021f3c7d626100041f3c027b626100045b0d1f3c027b626100045d13041613053810000000027b6f6100041105099e1105175813051105027b626100043fe3ffffff1613063818000000027b6f61000411068fd7000001254a175854110617581306110611043fdfffffff027b6f610004027b6261000428a74a0006161307161308382d0000001107027b6f61000411089458130711071f3c3e040000001f3c1307027b6361000411071759179c1108175813081108027b626100043fc6ffffff2a"

ls=s["dll"]["local_signature"]
assert (ls["token"],ls["standalone_sig_row_hex"],ls["blob_hex"])==(
    "0x11001107","fbce0200","07090812a408128634080808080808"
)
assert len(ls["locals"])==9
assert ls["locals"][0]=={"index":0,"metadata_type":"Int32"}
assert (ls["locals"][1]["typedef_rid"],ls["locals"][1]["type"],ls["locals"][1]["typedef_row_hex"])==(
    2306,"MatchSetting","01001000646c0000000000000903ce578749"
)
assert (ls["locals"][2]["typedef_rid"],ls["locals"][2]["type"],ls["locals"][2]["typedef_row_hex"])==(
    397,"COMLevelData","0100100063140000000000000903310d4410"
)
assert [x["metadata_type"] for x in ls["locals"][3:]]==["Int32"]*6

fields=s["dll"]["fields"]
assert [(x["token"],x["owner"],x["name"],x["signature_blob_hex"]) for x in fields]==[
 ("0x04006163","PlayerController_AI","rapidPushTbl","061d02"),
 ("0x04002AD1","GlobalWork","inst","061290c0"),
 ("0x04002AD2","GlobalWork","MatchSetting","0612a408"),
 ("0x04000D38","COMLevelDataManager","inst","06128638"),
 ("0x040057D6","MatchSetting","ComLevel","0608"),
 ("0x04000D33","COMLevelData","pushButtonNumPerSecond_Min","0608"),
 ("0x04000D34","COMLevelData","pushButtonNumPerSecond_Max","0608"),
 ("0x04006162","PlayerController_AI","rapidPushRate","0608"),
 ("0x0400616F","PlayerController_AI","itv_tbl","061d08")
]
fa=s["dll"]["field_accesses"]
assert len(fa)==22
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="cdc1b72f1fe728d903a08a26adc43ef79cecfd76e804c2c4de31b0c48586404c"

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
 ("0x0032","callvirt","0x06001049","FACT-0234"),
 ("0x0047","call","0x0600497B","FACT-0032"),
 ("0x00E9","call","0x06004AA7","FACT-0237")
]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="bd2dc1ae5dc6ed8d33aa24d9c1c37f2bcc913c0bfb52a06fcda815c7f0eeb6df"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"]) for x in refs]==[
 ("0x06005023","Process_PinfallDef","0x0030"),
 ("0x06005024","Process_SubmissionDef","0x0030"),
 ("0x06005026","Process_ContestOfStrength","0x0020"),
 ("0x06005027","Process_ExchangeOfStriking","0x0020")
]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="2e789241bd7737ce018112b13a13f2ea82fe94b8f156d1d6e90dce4f16df7441"
assert hashlib.sha256(("".join(x+"\n" for x in sorted({r["caller_token"] for r in refs}))).encode()).hexdigest()=="f93c47431bbc224c1fc332b07524951e4f1741e5a9de328ce0b58e8f2b8dbfb0"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(4,4)

c=s["capture_boundary"]
for k in [
 "playercontroller_ai_make_rapid_push_tbl_row_count",
 "comleveldatamanager_get_com_level_data_row_count",
 "matchrandom_range_row_count",
 "misc_shuffle_row_count",
 "playercontroller_ai_process_pinfall_def_row_count",
 "playercontroller_ai_process_submission_def_row_count",
 "playercontroller_ai_process_contest_of_strength_row_count",
 "playercontroller_ai_process_exchange_of_striking_row_count"
]:
    assert c[k]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI MAKE RAPID PUSH TBL SUMMARY: PASS")
