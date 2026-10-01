#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_theme_iterator_support.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_THEME_ITERATOR_SUPPORT_V1"
iters=s["dll"]["iterators"]
assert [x["type"] for x in iters]==["<CoChange_BGMandPlay>c__Iterator8","<CoChange_BGMandPlay_FromAssetBundle>c__Iterator9"]
assert [x["fields"]["current"]["token"] for x in iters]==["0x0400C242","0x0400C24A"]
assert [x["fields"]["disposing"]["token"] for x in iters]==["0x0400C243","0x0400C24B"]
assert [x["fields"]["pc"]["token"] for x in iters]==["0x0400C244","0x0400C24C"]
assert [m["token"] for m in iters[0]["methods"]]==["0x060074EB","0x060074EC","0x060074ED","0x060074EE"]
assert [m["token"] for m in iters[1]["methods"]]==["0x060074F1","0x060074F2","0x060074F3","0x060074F4"]
assert iters[0]["methods"][2]["code_sha256"]=="e86626c33062562b8370a39954a1cd69a0cf16f25abd8ed69745e512cd39449d"
assert iters[1]["methods"][2]["code_sha256"]=="901ca17e2ae4c9e392c1d7c503318763a7e507f7ad3595d277e4495bac74000a"
assert all(x["methods"][3]["code_sha256"]=="feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49" for x in iters)
assert s["dll"]["reset_exception"]["memberref_token"]=="0x0A0000EE"
print("DLL MENU SOUND THEME ITERATOR SUPPORT SUMMARY: PASS")
