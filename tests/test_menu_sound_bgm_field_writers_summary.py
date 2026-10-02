#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_bgm_field_writers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_BGM_FIELD_WRITERS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060052A3","0x003229D0",13,"e4b40d03b2d5fa1894f4bcdd314fe8860105a11edb0df6b7f260115e6f51abf9"),
 ("0x060052A5","0x00322A27",13,"26438a04e2990fa90e8ac47da1d35ac4bc09608c539517d58e490194a1731a18")]
assert m[0]["body_hex"]=="1780038700040280028700042a"
assert m[0]["parameters"]==[{"sequence":1,"name":"no","type":"MenuBGM","type_token":"0x02000A7B"}]
assert [x["field_token"] for x in m[0]["writes"]]==["0x04008703","0x04008702"]
assert m[1]["body_hex"]=="0280f68600040280f78600042a"
assert m[1]["parameters"]==[{"sequence":1,"name":"frm","type":"Int32"}]
assert [x["field_token"] for x in m[1]["writes"]]==["0x040086F6","0x040086F7"]
assert all((x["instruction_count"],x["branch_instruction_count"],x["call_instruction_count"])==(5,0,0) for x in m)
print("DLL MENU SOUND BGM FIELD WRITERS SUMMARY: PASS")
