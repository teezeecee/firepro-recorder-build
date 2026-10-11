#!/usr/bin/env python3
"""FACT-0275 original-DLL witness and registry constraints."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_wrestler_anm_data_array_entry.summary.json").read_text())
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text())
m=w["dll"]["method"];a=w["dll"]["window"];t=a["loop_tail"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_WRESTLER_ANM_DATA_ARRAY_ENTRY_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x039A","0x03CC",50,"bbf5b08e249f77f464d089386cab4f2ba9a56d0d19f053ace926eaa39a4b61a7")
assert (t["start_il"],t["end_exclusive_il"],t["length_bytes"],t["source_sha256"])==("0x06B3","0x06C5",18,"e59b7d577386dbb7056693ec9bed8e73836d43a92b9b8a126a02ffdd491cf04e")
assert [len(bytes.fromhex(x["source_hex"])) for x in a["segments"]]==[17,8,14,11]
assert "".join(x["source_hex"] for x in a["segments"])=="07077b547c00048d6e0a00027d7a7c000416130d3805030000077b7a7c0004110d734e520006a2077b7a7c0004110d9a130e"
assert (a["element_type"]["typedef_token"],a["element_type"]["name"])==("0x02000A6E","WrestlerAnmData")
assert [(x["token"],x["name"]) for x in a["source_fields"]]==[("0x04007C54","anmNum"),("0x04007C7A","anmData")]
assert (a["constructor"]["token"],a["constructor"]["signature_hex"])==("0x0600524E","200001")
assert (a["forward_branch"]["target_il"],t["back_edge_target_il"])==("0x06B8","0x03B3")
assert (a["array_entry_index_local"],a["array_entry_reference_local"])==(13,14)
assert sum(x["fact_id"]=="FACT-0275" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (ROOT/"canonical/facts/FACT-0275-skill-data-man-rsf-wrestler-anm-data-array-entry.json").exists()
print("SKILL DATA MAN RSF WRESTLER ANM DATA ARRAY ENTRY SUMMARY: PASS")
