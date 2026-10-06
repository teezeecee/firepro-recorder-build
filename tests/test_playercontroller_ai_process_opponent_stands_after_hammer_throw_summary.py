#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_opponent_stands_after_hammer_throw.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_OPPONENT_STANDS_AFTER_HAMMER_THROW_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FF2","0x002FB3C0","c0b32f0000008100f83b0a00db490000d93a","200002"
)
assert m["parameters"]==[]
assert m["return_type_metadata"]=="Boolean"
assert (m["impl_flags_raw"],m["method_attributes_raw"])==("0x0000","0x0081")
assert (m["header_format"],m["fat_header_bytes_raw"],m["max_stack"],m["init_locals"],m["local_signature_token"])==(
    "fat","13300300f80000001d110011",3,True,"0x1100111D"
)
assert (m["local_signature_row_hex"],m["local_signature_blob_hex"])==(
    "fdd00200","070712a78812a8f412863011a7c41d081185f008"
)
assert [x["metadata_type"] for x in m["locals"]]==[
    "Player","VenueSetting","AIParam","DamageLevelEnum_LMH","Int32[]","AIOpt_HammerThrough","Int32"
]
assert (m["code_size"],m["code_sha256"])==(
    248,"f417f4eab0e62c6e31057c8c5123b17c930240b8a0691685c70a1fc40ca4e7d3"
)
assert (m["instruction_count"],m["branch_instruction_count"],m["methoddef_call_site_count"],m["memberref_method_call_count"])==(72,9,6,0)

fa=s["dll"]["field_accesses"]
assert len(fa)==18
core_fa=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in fa]
assert hashlib.sha256(json.dumps(core_fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="09adedd34497a517e5eda5fa7692265274ca17b0572ee271a1575faf785712ff"

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
    ("0x0010","callvirt","0x06005065","FACT-0109"),
    ("0x0051","call","0x06004F9B","FACT-0038"),
    ("0x0075","call","0x0600495B","FACT-0245"),
    ("0x00C2","call","0x06004FAB","FACT-0244"),
    ("0x00D7","call","0x06004FA8","FACT-0243"),
    ("0x00EC","call","0x06004FAB","FACT-0244")
]
core_calls=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core_calls,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="63dbe63042cbe01294261895504ac2c2593622772fe4249d987207d61bb09369"
assert s["dll"]["external_memberrefs"]==[]

branches=s["dll"]["branch_map"]
assert len(branches)==9
assert hashlib.sha256(json.dumps(branches,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="bac692035b37c351ce27308838ffedb016a31527eec272d826fa8810df323b2a"
assert branches[3]=={
    "il":"0x0085","opcode":"switch",
    "targets":["0x00AB","0x00AB","0x00AB","0x00E1","0x00E1","0x00E1","0x00E1"]
}

refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06004FC8","AIActFunc_CounterAttack","0x01C6","call"),
    ("0x06004FE1","Process_Grapple_Front","0x0190","call"),
    ("0x06004FE3","Process_Grapple_BackAtk","0x0147","call"),
    ("0x0600502B","Update","0x0276","call")
]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="a8838106a8579298d1c4c960f727ed2b0f572ad9f7cd3abd4c8fee500892d4e4"
assert hashlib.sha256(("0x06004FC8\n0x06004FE1\n0x06004FE3\n0x0600502B\n").encode()).hexdigest()=="1a1b66420b281902d96e6d193ed31e681f7f9a2e1647fa0eadfa82f2574c40c6"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(4,4)

c=s["capture_boundary"]
for k,v in c.items():
    if k.endswith("_row_count"):
        assert v==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI PROCESS OPPONENT STANDS AFTER HAMMER THROW SUMMARY: PASS")
