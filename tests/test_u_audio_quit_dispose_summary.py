#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_quit_dispose.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_QUIT_DISPOSE_V1"
q=s["dll"]["on_application_quit"]; d=s["dll"]["dispose"]
assert (q["token"],q["rva"],q["code_size"],q["code_sha256"])==("0x060052EB","0x00325E1F",7,"7a7dcc5d4b3ee0bb1933833a4e1db71ee2f4720b7d7084aea7ccca1bee9c4ee4")
assert q["call"]=={"token":"0x060052EC","name":"Dispose","call_il":"0x0001"}
assert (d["token"],d["rva"],d["code_size"],d["code_sha256"])==("0x060052EC","0x00325E27",59,"e67d4211a0c7ec2b2eb5a67f694a81c4e43c78972d036dd2e856f8573244884c")
assert d["fields"]=={"read_fully_stream":"0x040087EF","backend":"0x040087E3","loaded_target":"0x040087F1"}
assert d["calls"]["stream_close"]["token"]=="0x0A000154"
assert d["calls"]["backend_dispose"]["token"]=="0x0A000FD5"
print("DLL U AUDIO QUIT DISPOSE SUMMARY: PASS")
