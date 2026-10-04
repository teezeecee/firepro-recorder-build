#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_is_happen_power_competition.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_IS_HAPPEN_POWER_COMPETITION_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FD3","0x002F8D90","908d2f00000096007e390a00634a0000c93a","000002"
)
assert m["parameters"]==[]
assert m["return_type"]=={"metadata_type":"Boolean"}
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0096","fat","133002002800000006110011",2,"0x11001106"
)
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    40,"6d6d6ede32b0294d70267f18c929adf5a196a0ca8f720d77547385aa1df8c414",
    "7ed12a00047bd22a00040a7e380d0004067bd65700046f491000060b077b350d000428554900062a"
)
ls=s["dll"]["local_signature"]
assert (ls["token"],ls["standalone_sig_row_hex"],ls["blob_hex"])==("0x11001106","f2ce0200","070212a408128634")
assert [(x["index"],x["typedef_rid"],x["type"],x["typedef_row_hex"]) for x in ls["locals"]]==[
    (0,2306,"MatchSetting","01001000646c0000000000000903ce578749"),
    (1,397,"COMLevelData","0100100063140000000000000903310d4410")
]
assert [(x["token"],x["owner"],x["name"],x["field_row_hex"],x["signature_blob_hex"]) for x in s["dll"]["fields"]]==[
    ("0x04002AD1","GlobalWork","inst","1600062201008d1a0000","061290c0"),
    ("0x04002AD2","GlobalWork","MatchSetting","0600646c00007c1a0000","0612a408"),
    ("0x04000D38","COMLevelDataManager","inst","1600062201007d0a0000","06128638"),
    ("0x040057D6","MatchSetting","ComLevel","0600c54d000001000000","0608"),
    ("0x04000D35","COMLevelData","powerCompetitionProbability","0600103e010001000000","0608")
]
fa=s["dll"]["field_accesses"]
assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[
    ("0x0000","ldsfld","0x04002AD1"),("0x0005","ldfld","0x04002AD2"),
    ("0x000B","ldsfld","0x04000D38"),("0x0011","ldfld","0x040057D6"),
    ("0x001D","ldfld","0x04000D35")
]
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="0d82e900d994aa16f6dcba6c1997d958f532f93942c1c3a2a2517363747a57ea"
calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
    ("0x0016","callvirt","0x06001049","FACT-0234"),("0x0022","call","0x06004955","FACT-0025")
]
call_core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(call_core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="17c876cb0d2798f3c6cf17a2b3a7c251f68043c89721221f0424eb92fddf495f"
assert s["dll"]["external_memberrefs"]==[]
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_type"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06004EF4","Player","CheckStartPowerCompetition","0x0091","call")
]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="c82055581e56aa04315cd68fcbcd0be36b84b86173219a87aab1cc8c2674ad9f"
assert s["dll"]["normalized_caller_token_set_sha256"]=="544c8e0063de5501ba82bd3fffb3548fdcf570f7061c0b4ed01a33a29e84bca9"
c=s["capture_boundary"]
assert c["playercontroller_ai_is_happen_power_competition_row_count"]==0
assert c["player_check_start_power_competition_row_count"]==0
assert c["comleveldatamanager_get_com_level_data_row_count"]==0
assert c["matchmisc_rate100_check_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI IS HAPPEN POWER COMPETITION SUMMARY: PASS")
