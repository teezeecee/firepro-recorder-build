"""FACT-0287 matching original DLL resource route/source chain static assertions."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_load_rsf_file_resource_route.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"];m=a["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_DATA_MAN_LOAD_RSF_FILE_RESOURCE_ROUTE_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525C",55,"7996e6e4e0d6b04bcacac4fbd8f2431bc470526c80c09533d98e626b9a86642d")
assert [len(bytes.fromhex(x["il_hex"])) for x in m["segments"]]==[22,23,8,2]
assert a["resource_literal"]["text"]=="WrestlerAnimation/"
assert set(a["memberrefs"])=={"0x0A000012","0x0A0006DA","0x0A00014F"}
assert set(a["typerefs"])=={"0x010000E4","0x010000C2"}
assert a["exception_handler"]["section_hex"]=="01100000000000002d2d0008c2000001"
assert [(x["token"],x["target_token"],x["call_il"]) for x in a["call_chain"]]==[("0x06005255","0x0600525B","0x001D"),("0x0600525B","0x0600525C","0x00AD"),("0x0600525C","0x0600525F","0x0022")]
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert sum(x["fact_id"]=="FACT-0287" for x in r["families"])==1
assert (ROOT/"canonical/facts/FACT-0287-skill-data-man-load-rsf-file-resource-route.json").exists()
print("SKILL DATA MAN LOAD RSF FILE RESOURCE ROUTE SUMMARY: PASS")
