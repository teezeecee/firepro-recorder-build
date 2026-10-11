import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_disp_info_array_entry.summary.json").read_text())
r=json.loads((R/"canonical/transition_registry.json").read_text())
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_DISP_INFO_ARRAY_ENTRY_V1" and w["source_ids"]==["DLL-001"]
assert (w["il_window"]["start"],w["il_window"]["end_exclusive"],w["il_window"]["bytes"],w["il_window"]["sha256"])==("0x0470","0x04A6",54,"bc0ed2c241c89d1d81ff237dbcbf6177383aef1940cd361823a24e046dd65692")
assert (w["loop_tail"]["bytes"],w["loop_tail"]["sha256"])==(20,"e153d66b676c0e812c5ef739a71aa380c4bf3284de2e7ec5e1b8a1ab3889ef2c")
assert [len(bytes.fromhex(x["hex"])) for x in w["segments"]]==[19,8,15,12]
assert [x["name"] for x in w["metadata"]["fields"]]==["formNum","formDispList"]
assert w["metadata"]["type"]["name"]=="FormDispInfo"
assert (w["forward_branch"]["target"],w["back_branch"]["target"])==("0x06A4","0x048B")
assert sum(x["fact_id"]=="FACT-0277" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (R/"canonical/facts/FACT-0277-skill-data-man-rsf-form-disp-info-array-entry.json").exists()
print("SKILL_DATA_MAN_RSF_FORM_DISP_INFO_ARRAY_ENTRY_SUMMARY: PASS")
