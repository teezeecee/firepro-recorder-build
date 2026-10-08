#!/usr/bin/env python3
"""Static witness integrity for FACT-0257; source-level verification is separate."""
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_go_back_grapple.summary.json").read_text(encoding="utf-8"))
d=w["dll"];m=d["method"];body=bytes.fromhex(m["body_hex"])
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_GO_BACK_GRAPPLE_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["fat_header_hex"],m["signature_blob_hex"])==("0x06004FB1","0x002F634C","13300400eb000000f3100011","200002")
assert m["local_signature_blob_hex"]=="070212a78811a7dc"
assert len(body)==m["code_size"]==235
assert hashlib.sha256(body).hexdigest()==m["code_sha256"]=="05aa37f29b638f8da45743303251598eea9a5bf501388a75d7f0208ea0a2175c"
assert len(d["instructions"])==74 and len(d["branches"])==9 and len(d["fields"])==20
assert len(d["direct_methoddef_calls"])==6 and d["memberref_method_call_count"]==0
assert [(x["token"],x["canonical_fact_id"]) for x in d["direct_methoddef_calls"]]==[("0x06005065","FACT-0109"),("0x06004FF4","FACT-0252"),("0x06004FAD","FACT-0044"),("0x06004FD7","FACT-0254"),("0x06004FD9","FACT-0255"),("0x06004F9E","FACT-0256")]
assert len(d["direct_in_assembly_references"])==1
assert (d["direct_in_assembly_references"][0]["opcode"],d["direct_in_assembly_references"][0]["call_il"])==("ldftn","0x0073")
assert w["capture_boundary"]["checked_names_event_row_count"]==0 and w["capture_boundary"]["promoted_as_evidence"] is False
assert (ROOT/"canonical/facts/FACT-0257-playercontroller-ai-go-back-grapple.json").exists()
print("PLAYERCONTROLLER AI GO BACK GRAPPLE SUMMARY: PASS")
