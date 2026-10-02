#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_small_read_accessors.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_SMALL_READ_ACCESSORS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060052D1","0x00325736",10,"31bdeabeee44f72dd1178652ad52ed510e193721cfb4d8a60279ab7efe50000a"),
 ("0x060052CD","0x0032569C",12,"f0f5455681d30721da8b169ee1b718bbfa4efb609ee5cef8b3a702da1bbd4ec2"),
 ("0x060052DB","0x0032581A",12,"20440b8eac4fe338ed6167908e7ef4c7029862c4280a8680173021bae4ca21a0")]
assert m[0]["field"]["token"]=="0x040087E9"
assert m[1]["call"]=={"token":"0x0A000FAF","resolved":"uAudio.uAudio_backend.uAudio.get_SongLength","call_il":"0x0006"}
assert m[2]["call"]=={"token":"0x0A0002A1","resolved":"UnityEngine.AudioSource.get_volume","call_il":"0x0006"}
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
print("DLL U AUDIO SMALL READ ACCESSORS SUMMARY: PASS")
