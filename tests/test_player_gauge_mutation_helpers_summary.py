#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_gauge_mutation_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_GAUGE_MUTATION_HELPERS_V1"
ms=s["dll"]["methods"]; assert len(ms)==10
expected={
"AddHP":("0x06004ECB",118,"7bea96e74624b8014aab919f755fba46681651c5aa2227665f3809dd0eecd5b9"),
"SetHP":("0x06004ECC",111,"9464ea04471ecb7c12d842bd75de42674848d322649a884fccbbf1d266e36b9a"),
"AddBP":("0x06004ECD",118,"f7f25fb62c16540e17a6f0dfb0eb138bbdc845c7af43eac9d5035c4686ecb1e6"),
"SetBP":("0x06004ECE",111,"a2b699b33928252a7760f62e86cbdc9a72aaa080f2cd3ea9d62ba2f827cec706"),
"AddSP":("0x06004ECF",118,"2316bc2161b5cad37f892c724cff047f7599c5cefb0c4929e40f52f5589b7b36"),
"SetSP":("0x06004ED0",111,"aa4a13340001d7b25181e1c10a729c1436490b51a6b8c821f5098db7b4eed89b"),
"AddHP_Neck":("0x06004ED4",81,"06811329438dd3f627c163e6311e52ce59fae1f2e6ea89f4a6a8a74d9f007ca0"),
"AddHP_Arm":("0x06004ED5",81,"10d9eb1af8841d2f9302a35ce081ca00d03f96bb4ddba9050bd4be5138d7b1ef"),
"AddHP_Waist":("0x06004ED6",81,"6252e60a604afd0da73eff0df982cf7cb310863d0c5e2f1f6d279b69de9bd96f"),
"AddHP_Leg":("0x06004ED7",81,"ea3412cf696898ca16a9f88e35f8c1aac099ba393a324b7d23afb9c0ce1a00a8")}
for m in ms:
 assert (m["token"],m["size"],m["sha"])==expected[m["name"]]
assert s["dll"]["shared"]["is_immortal_field_token"]=="0x0400605E"
assert s["dll"]["shared"]["clamp_low"]==0.0 and s["dll"]["shared"]["clamp_high"]==65535.0
assert s["dll"]["shared"]["low_continue_opcode"]=="bge.un" and s["dll"]["shared"]["high_continue_opcode"]=="ble.un"
assert [x["name"] for x in ms if x["kind"]=="add_limb"]==["AddHP_Neck","AddHP_Arm","AddHP_Waist","AddHP_Leg"]
assert s["caller_bridges"][0]["fact_id"]=="FACT-0020" and s["caller_bridges"][1]["fact_id"]=="FACT-0026"
print("DLL PLAYER GAUGE MUTATION HELPERS SUMMARY: PASS")
