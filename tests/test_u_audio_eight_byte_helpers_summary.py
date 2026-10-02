#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_eight_byte_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_EIGHT_BYTE_HELPERS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060052D4","0x0032574F",8,"a7ef316dd7fe39b4eaeda4d2e2e77ba05490faf1bfb2ef51a007d2e76bcb182f"),
 ("0x060052E2","0x0032588D",8,"58193cf76ec4ea1593941160a6d4a33e52eabe8941423467e4856a4a1d58a521"),
 ("0x060052E5","0x003259BD",8,"79994be6176e273a75d4c1d2971a5a3e1dbd12aa3428791124fd0d7429e79caf")]
assert [x["methoddef_row_hex"] for x in m]==[
 "4f5732000000810045630a005c480000553d",
 "8d5832000000e601f1630a00744801005a3d",
 "bd5932000000e60103640a00794800005c3d"]
assert m[1]["parameters"]==[{"sequence":1,"name":"timeIN","type":"System.TimeSpan"}]
assert m[1]["call"]=={"token":"0x060052D7","name":"set_CurrentTime","fact_id":"FACT-0141","call_il":"0x0002"}
assert m[2]["parameters"]==[{"sequence":1,"name":"targetFileIN","type":"String"}]
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
print("DLL U AUDIO EIGHT BYTE HELPERS SUMMARY: PASS")
