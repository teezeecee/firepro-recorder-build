"""FACT-0292 reproducible exact original 960-byte bank count data from source witness."""
import hashlib,json,struct,collections
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/anm_bank_data_file_num_tbl_source_120_pairs.summary.json").read_text())
fact=json.loads((ROOT/"canonical/facts/FACT-0292-anm-bank-data-file-num-tbl-source-120-pairs.json").read_text())
registry=json.loads((ROOT/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["static_constructor"];r=d["field_rva"]
assert (fact["fact_id"],fact["status"])==("FACT-0292","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_ANM_BANK_DATA_FILE_NUM_TBL_SOURCE_120_PAIRS_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x06005246",25,"fbb695a6ddc0ccb80cf02a59b0d1761abec6590b352227e72fef7665be148393")
assert hashlib.sha256(bytes.fromhex(m["il_hex"])).hexdigest()==m["code_sha256"]
assert d["source_array_field"]["token"]=="0x0400B8F6" and d["destination_field"]["token"]=="0x0400656D"
assert d["array_type_spec"]["signature_hex"]=="14080200020000"
assert (r["row_hex"],r["rva"],r["file_offset"],r["source_bytes"])==("c0327b00f6b8","0x007B32C0","0x007AFEC0",960)
pairs=d["bank_file_pairs"]
assert len(pairs)==120 and len({x[0] for x in pairs})==120
assert all(len(x)==2 and all(isinstance(k,int) for k in x) for x in pairs)
packed=struct.pack("<240i",*(n for p in pairs for n in p))
assert len(packed)==960 and hashlib.sha256(packed).hexdigest()==r["source_sha256"]=="107e6a82ea8141420999dbb5c61ed597cdcb4d9cc74c941b1153ec5bd5ed215b"
assert {str(k):v for k,v in collections.Counter(x[1] for x in pairs).items()}==d["file_count_histogram"]=={"1":78,"2":28,"3":14}
assert len({x["family_id"] for x in registry["families"]})==len(registry["families"])
assert sum(x["fact_id"]=="FACT-0292" for x in registry["families"])==1
print("ANM BANK DATA FILE NUM TBL ORIGINAL 120 PAIRS SUMMARY: PASS")
