"""FACT-0290 original DLL-only AnmBankData bank file count lookup static witness."""
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/anm_bank_data_get_anm_file_num_lookup.summary.json").read_text())
f=json.loads((ROOT/"canonical/facts/FACT-0290-anm-bank-data-get-anm-file-num-lookup.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_ANM_BANK_DATA_GET_ANM_FILE_NUM_LOOKUP_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x06005244",62,"e14414c9db821065dd7627fb267798d6659affcb7acce76019717bd19664ca9c")
assert hashlib.sha256(bytes.fromhex(m["il_hex"])).hexdigest()==m["code_sha256"]
assert [len(bytes.fromhex(x["il_hex"])) for x in m["segments"]]==[7,18,13,22,2]
assert [x["target_il"] for x in d["branches"]]==["0x002A","0x0026","0x0007"]
assert [(k,v["name"]) for k,v in d["memberrefs"].items()]==[("0x0A000716","Get"),("0x0A00087C","get_Length")]
assert (d["field"]["token"],d["field"]["name"])==("0x0400656D","FileNumTbl")
assert d["fallback"]=={"start_il":"0x003C","bytes":"172a","returns_literal":1}
assert d["parent_call"]["call_hex"]=="2844520006"
assert (f["fact_id"],f["status"])==("FACT-0290","PROVEN_DLL")
assert sum(x["fact_id"]=="FACT-0290" for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
print("ANM BANK DATA GET ANM FILE NUM LOOKUP SUMMARY: PASS")
