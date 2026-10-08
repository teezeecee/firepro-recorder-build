#!/usr/bin/env python3
"""Static witness test for FACT-0256. Raw DLL/R6 check lives in the separate prover."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_set_ai_act_go_grapple.summary.json"
w=json.loads(W.read_text(encoding="utf-8"))
d=w["dll"];m=d["method"]
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_GO_GRAPPLE_V1"
assert w["source_ids"]==["DLL-001"]
assert d["sha256"]=="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
assert (m["token"],m["rva"],m["signature_blob_hex"],m["tiny_header_hex"])==("0x06004F9E","0x002F5FC6","20030111870c11a7dc08","5e")
assert m["parameter_count"]==3 and m["signature_types"]==["void","SkillSlotEnum","GoAroundDir","Int32"]
assert [r["name"] for r in m["parameter_rows"]]==["skill","dir","tm"]
assert (m["parameter_rows"][0]["raw_row_hex"],m["parameter_rows"][1]["raw_row_hex"],m["parameter_rows"][2]["raw_row_hex"])==("0000010029a40200","00000200ee190600","00000300d7610700")
body=bytes.fromhex(m["body_hex"])
assert len(body)==m["code_size"]==23 and m["decoded_instruction_count"]==11
assert hashlib.sha256(body).hexdigest()==m["code_sha256"]=="978e82da32179445718786287df804ca334ac6f1889e726bec8774e5a13ccf12"
assert body==bytes.fromhex("021705289d4f000602037d6061000402047d4e6100042a")
assert [(v["il"],v["opcode"]) for v in d["instructions"]]==[
 ("0x0000","ldarg.0"),("0x0001","ldc.i4.1"),("0x0002","ldarg.3"),
 ("0x0003","call"),("0x0008","ldarg.0"),("0x0009","ldarg.1"),
 ("0x000A","stfld"),("0x000F","ldarg.0"),("0x0010","ldarg.2"),
 ("0x0011","stfld"),("0x0016","ret")]
assert len(d["direct_methoddef_calls"])==1
assert d["direct_methoddef_calls"][0]["canonical_fact_id"]=="FACT-0043"
assert d["direct_methoddef_calls"][0]["token"]=="0x06004F9D"
assert d["memberref_method_call_count"]==0 and d["branches"]==[]
assert [(x["token"],x["name"],x["il"]) for x in d["fields"]]==[
 ("0x04006160","nextSkill","0x000A"),("0x0400614E","aiActPrm","0x0011")]
refs=d["direct_in_assembly_references"]
assert len(refs)==d["direct_reference_count"]==d["direct_caller_method_count"]==6
assert [(x["caller_token"],x["call_il"]) for x in refs]==[
 ("0x06004FB0","0x0103"),("0x06004FB1","0x00E4"),("0x06004FC4","0x0083"),
 ("0x06004FC5","0x02D0"),("0x06004FF6","0x013F"),("0x06005009","0x022C")]
sha=lambda x:hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":")).encode()).hexdigest()
assert sha(refs)==d["direct_reference_digest"]=="8b639c74dc7bc8eba15f8ca12a7bceaba095ba45d69aaa2b5ef8eaccc50650be"
assert hashlib.sha256(("\n".join(sorted({x["caller_token"] for x in refs}))+"\n").encode()).hexdigest()==d["caller_token_set_digest"]=="6e79f49c660d7087748e3c0b3ccdfee1deecf8edebc7b9f960f73f41d78a136a"
assert w["capture_boundary"]["checked_names_event_row_count"]==0
assert w["capture_boundary"]["promoted_as_evidence"] is False
assert (ROOT/"canonical"/"facts"/"FACT-0256-playercontroller-ai-set-ai-act-go-grapple.json").exists()
print("PLAYERCONTROLLER AI SET AI ACT GO GRAPPLE SUMMARY: PASS")
