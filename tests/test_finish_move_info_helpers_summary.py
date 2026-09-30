#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"finish_move_info_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_FINISH_MOVE_INFO_HELPERS_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x060048D1","0x002A4DFD",29,"12183b4682dd4873916a8e3a0305c01ed4c53de737a481b94c7f3c47ee46c1c5")
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==("0x060048D2","0x002A4E1B",49,"f5ede8840d753fddbc5e58b18de45f8b9f3afefc5efcd4f1fd3666a6bd9f2476")
assert s["dll"]["fields"]==[
 {"name":"category","token":"0x040056CB"},{"name":"skillID","token":"0x040056CC"},{"name":"plIdx","token":"0x040056CD"},{"name":"skillOwnerPlIdx","token":"0x040056CE"}]
assert s["dll"]["clear"]["raw_reset_value"]==-1
assert s["dll"]["set"]["field_order"]==["category","skillID","plIdx","skillOwnerPlIdx"]
assert [x["il"] for x in s["dll"]["apply_damage_bridge"]["calls"]]==["0x05CD","0x05E0","0x060A"]
print("DLL FINISH MOVE INFO HELPERS SUMMARY: PASS")
