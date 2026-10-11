"""FACT-0279 original-DLL source-only static witness and registry gate."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_index_dual_word_read.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];m=w["dll"]["method"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_INDEX_DUAL_WORD_READ_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x04CC","0x04F1",37,"8588bd8b25ff5e6e65b25ec5c33cfecb3fbaf75bc36ffacc6583334b38a3573b")
assert [len(bytes.fromhex(x["il_hex"])) for x in a["segments"]]==[19,14,4]
assert [x["name"] for x in a["segments"]]==["source_word_assign_formIdx","same_source_word_assign_local17","advance_cursor_two_after_both_reads"]
assert (a["cursor_local"],a["form_entry_local"],a["word_local"])==(2,16,17)
assert (a["field"]["token"],a["field"]["name"],a["field"]["signature_hex"])==("0x04007CD9","formIdx","0608")
assert sum(x["fact_id"]=="FACT-0279" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0279-skill-data-man-rsf-form-index-dual-word-read.json").exists()
print("SKILL DATA MAN RSF FORM INDEX DUAL WORD READ SUMMARY: PASS")
