#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_match_se_factory_support.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_MATCH_SE_FACTORY_SUPPORT_V1"
assert s["dll"]["owner_type"]=={"name":"<Load_MatchSe>c__Iterator0","token":"0x02000F65"}
f=s["dll"]["factory"]
assert (f["token"],f["rva"],f["code_size"],f["code_sha256"])==("0x06005284","0x00321A30",15,"65d2fa09b6d7e4734ea6ced8c7df63053cd00416b490ac5bbbebc2900df6eca3")
assert f["constructor_token"]=="0x060074B9" and f["captured_this_field"]=="0x0400C1F1"
m=s["dll"]["support_methods"]
assert [x["token"] for x in m]==["0x060074B9","0x060074BB","0x060074BC","0x060074BD","0x060074BE"]
assert m[1]["code_sha256"]==m[2]["code_sha256"]=="2a8bce63c14acba20ed3137df6f67799c50ca87fe09910f877deff0c540107c9"
assert s["dll"]["open_execution_method"]["token"]=="0x060074BA"
assert s["dll"]["fact_0160_related_string_observation"]["relationship_status"]=="NAME_ONLY_EXTERNAL_DISPATCH_NOT_DIRECT_CALL"
print("DLL MENU SOUND LOAD MATCH SE FACTORY SUPPORT SUMMARY: PASS")
