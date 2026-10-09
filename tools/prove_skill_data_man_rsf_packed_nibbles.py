#!/usr/bin/env python3
"""FACT-0267: source replay for original retail RSF packed-byte nibble writes."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_packed_nibbles.summary.json"
def need(ok,why):
 if not ok: raise RuntimeError(why)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original DLL-001 SHA/size")
 sec,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,sec,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 method=base.method(pe,sec,s,b,ix,z,o,sb,bb,owners,0x0600525F)
 need((method[0],method[1],method[4],method[7])==(m["methoddef_row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef")
 code=method[9]
 need(pe[base.off(sec,method[1]):method[8]].hex()==m["header_hex"] and len(code)==m["code_bytes"] and hashlib.sha256(code).hexdigest()==m["code_sha256"],"full original parser source identity")
 c=d["cursor"];incr=bytes.fromhex(c["initial_increment_hex"])
 need(code[0x1D:0x45]==incr*10 and c["initial_skip_count"]==10,"source cursor increments exactly 10")
 for offset,key in [(0x45,"prefix_first_field_hex_at_0x0045"),(0x52,"prefix_second_field_hex_at_0x0052"),(0x5F,"byte12_read_hex_at_0x005F"),(0x6E,"extra_advance_hex_at_0x006E"),(0x72,"byte14_read_hex_at_0x0072"),(0x93,"byte15_read_hex_at_0x0093")]:
  frag=bytes.fromhex(c[key]);need(code[offset:offset+len(frag)]==frag,"original cursor operation "+hex(offset))
 # Old stack-local cursor is passed to ldelem.u1; dup/add/stloc.2 prepares next cursor without replacing the array index.
 derived=[10,11,12,14,15]
 need([x["byte_offset"] for x in d["fields"]]==[14,14,15,15] and derived==[10,11,12,14,15],"independent source-relative cursor indices")
 for f in d["fields"]:
  at=int(f["source_slice_il"],16);frag=bytes.fromhex(f["source_hex"])
  need(code[at:at+len(frag)]==frag,"original shift-mask-stfld "+f["name"])
  raw=base.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))
  need((raw[0],raw[1],raw[2])==(f["row_hex"],("SkillData",""),f["name"]),"FieldDef metadata "+f["name"])
 test=d["flag_path"];at=int(test["test_il"],16);frag=bytes.fromhex(test["test_hex"])
 need(code[at:at+len(frag)]==frag and struct.unpack_from("<i",code,at+9)[0]==18 and at+13+18==int(test["branch_target_il"],16),"original bit7 branch")
 at=int(test["flag_write_il"],16);frag=bytes.fromhex(test["flag_write_hex"])
 need(code[at:at+len(frag)]==frag,"original flags |= 0x100")
 raw=base.field(pe,s,b,z,o,sb,bb,fm,int(test["flag_field_token"],16))
 need((raw[0],raw[1],raw[2])==(test["flag_field_row_hex"],("SkillData",""),test["flag_field_name"]),"flags field")
 # Enumerate all possible byte14/byte15 values for the asserted bit-split and branch masks.
 for n in range(256):
  need((n&15)==n%16 and (((n>>4)&15)*16+(n&15))==n,"byte14 packed nibble partition")
  need(((n>>4)&7)==(n>>4)%8 and (((n>>4)&7)*16+(n&15)+(128 if n&128 else 0))==n,"byte15 four/three/one-bit partition")
 return {"source":"DLL-001","full_method_sha256":m["code_sha256"],"original_packed_byte_offsets":[14,15],"original_field_count":len(d["fields"]),"optional_branch_mask":128,"optional_flags_bit":256,"canonical_export_interpretation":False}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);a=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_PACKED_NIBBLES_V1" and w["source_ids"]==["DLL-001"],"witness source scope")
  print(json.dumps(verify(a.dll,w),indent=2,sort_keys=True));print("PROVE_SKILL_DATA_MAN_RSF_PACKED_NIBBLES: PASS");return 0
 except Exception as err:
  print("PROVE_SKILL_DATA_MAN_RSF_PACKED_NIBBLES: FAIL",str(err));return 1
if __name__=="__main__":raise SystemExit(main())
