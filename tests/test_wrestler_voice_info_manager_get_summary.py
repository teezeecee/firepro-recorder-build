#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_info_manager_get.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_INFO_MANAGER_GET_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060011E7","row_hex":"5cf10600000086006f8e08004ca60100a00d","rva":"0x0006F15C"}
m=s["dll"]["method"]
assert (m["signature_blob_hex"],m["code_size"],m["code_sha256"])==("20011287c011aa3c",79,"28ecb121c6b122a6a493c0e865d1b061d3679204933aad2909bd7759801e48ea")
assert m["parameters"]==[{"sequence":1,"name":"type","type":"WrestlerVoiceTypeEnum","type_token":"0x02000A8F"}]
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"])==("0x001B",2,"0x1100034C")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(27,5,4)
assert s["dll"]["fields"]["list"]["token"]=="0x040011E7"
assert s["dll"]["fields"]["item_type"]["token"]=="0x040011DD"
eh=s["dll"]["exception_section"]
assert (eh["size_bytes"],eh["sha256"],eh["clause"]["kind"])==(16,"047cd8520a6ef4751de3efd2feb22a33873fdd1bdf86a56aa084a7da14f3af68","finally")
assert [x["call_il"] for x in s["dll"]["fact_0178_bridges"]]==["0x013B","0x0464"]
print("DLL WRESTLER VOICE INFO MANAGER GET SUMMARY: PASS")
