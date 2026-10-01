#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"refereeman_population.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREEMAN_POPULATION_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["code_size"]) for x in m]==[("0x060050B1",19),("0x060050B3",7),("0x060050B4",1),("0x060050B5",39)]
assert m[0]["code_sha256"]=="41af045848eb62f4e23c69e03c31ef3b97d03f719029ccc12ba8664223d8ad0f"
assert m[1]["code_sha256"]=="7f2f8b8a300d684c753bf13af8b5395f7de72f88526eeee171860bcef5004548"
assert m[2]["code_sha256"]=="684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1"
assert m[3]["code_sha256"]=="cbd7b30a0f79c0a5cb7c5459a6cb8462f5df1e30a023aefa52826ebce99fd7a6"
assert s["dll"]["constructor"]["effect"][0]=="this.RefereeObj = new Referee[1]"
assert s["dll"]["awake"]["effect"]=="RefereeMan.inst = this"
assert s["dll"]["start"]["effect"]=="ret only"
assert s["dll"]["create_referee"]["raw_index"]==0
assert s["dll"]["create_referee"]["instantiate"]["methodspec_token"]=="0x2B000051"
assert s["dll"]["create_referee"]["component"]["methodspec_token"]=="0x2B0003B9"
assert s["dll"]["fact_0065_bridge"]["fact_id"]=="FACT-0065"
print("DLL REFEREEMAN POPULATION SUMMARY: PASS")
