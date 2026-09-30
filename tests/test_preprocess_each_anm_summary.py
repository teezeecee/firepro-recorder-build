#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"preprocess_each_anm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_R6_PREPROCESS_EACH_ANM_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E78" and m["rva"]=="0x002DB11C"
assert m["code_size"]==1149 and m["code_sha256"]=="3dd3f334be363345a7de654b8a11ec29207937ba4dc5bbbba6e2f95eddd1ac9c"
assert m["parameters"]==[]
sel=s["dll"]["selector"]
assert len(sel["case_targets"])==20
assert sel["case_targets"]["1"]=="0x008B" and sel["case_targets"]["20"]=="0x046C"
assert len(s["dll"]["case_table"])==20
assert s["dll"]["call_site_counts"]["Player.ChangeState"]==16
assert s["dll"]["start_anm_bridge"]["method_call_count"]==1
r=s["r6"]
assert r["preprocess_each_anm_event_count"]==0
assert r["start_anm_calls"]==5333
assert r["start_anm_with_direct_Player_ChangeState_child"]==2
assert r["start_anm_without_direct_traced_child"]==5331
assert [x["start_anm_pre_line"] for x in r["observed_child_records"]]==[96086,321684]
w=s["witness_digest"]
assert w["record_count"]==2 and w["byte_count"]==172
assert w["sha256"]=="ccb5f70b041db4574dd710212922c4d233dcf24c28d168ddf9518fcdb1d67919"
print("PREPROCESS EACH ANM SUMMARY: PASS")
