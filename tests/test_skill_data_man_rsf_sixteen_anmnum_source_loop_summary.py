#!/usr/bin/env python3
"""FACT-0274 static witness, bounded source region and unique registry."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_sixteen_anmnum_source_loop.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"];segs=a["segments"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_SIXTEEN_INT32_ANMNUM_SOURCE_LOOP_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x0361","0x039A",57,"9341a572133ddfaaab1be56708be076289f15ca2c03a3845073a1e78c396b690")
assert (a["array_length"],a["array_local"],a["index_local"],a["source_cursor_local"])==(16,11,12,2)
assert a["postincrement_old_cursor"] and (a["first_relative_input_byte"],a["last_relative_input_byte"])==(48,63)
assert [x["name"] for x in segs]==["init_int32_array_and_index","jump_to_loop_condition","old_cursor_unsigned_byte_to_int32_element","increment_iteration_index","loop_while_less_than_sixteen","call_original_GetAnmNum_and_store_field"]
assert [len(bytes.fromhex(x["il_hex"])) for x in segs]==[12,5,12,6,9,13]
assert sum(len(bytes.fromhex(x["il_hex"])) for x in segs)==57
assert (segs[1]["branch_target_il"],segs[4]["branch_target_il"])==("0x0384","0x0372")
assert (a["array_type"]["typeref_token"],a["array_type"]["name"],a["array_type"]["element_store_opcode"])==("0x010000D7","Int32","stelem.i4")
assert a["read_opcode"]=="ldelem.u1" and (a["target_method"]["methoddef_token"],a["target_method"]["signature_hex"])==("0x06005265","0001081d08")
assert (a["destination_field"]["fielddef_token"],a["destination_field"]["name"])==("0x04007C54","anmNum")
assert sum(x["fact_id"]=="FACT-0274" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0274-skill-data-man-rsf-sixteen-anmnum-source-loop.json").exists()
print("SKILL DATA MAN RSF SIXTEEN ANMNUM SOURCE LOOP SUMMARY: PASS")
