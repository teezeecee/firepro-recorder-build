#!/usr/bin/env python3
"""FACT-0268 retail DLL source-byte replay. No proprietary data embedded."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_attack_byte_run.summary.json"
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original SHA-pinned DLL-001")
 ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
 sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 meth=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F)
 need((meth[0],meth[1],meth[4],meth[7])==(m["methoddef_row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef metadata")
 body=meth[9]
 need(pe[base.off(ss,meth[1]):meth[8]].hex()==m["header_hex"] and len(body)==m["code_size"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"complete original parser IL SHA")
 # The prior FACT-0267 bit7 false edge and true fallthrough both reach +0x00D2.
 need(body[0xB3:0xC0].hex()=="110420800000005f3912000000","prior source high-bit test")
 need(0xBB+5+struct.unpack_from("<i",body,0xBC)[0]==0xD2,"prior false branch directly joins nine writes")
 need(body[0xC0:0xD2].hex()=="07257b557c00042000010000607d557c0004","prior flag write falls through")
 fs=d["field_writes"];need(len(fs)==9,"nine fields")
 prefix=bytes.fromhex("0703082517580c917d")
 for i,f in enumerate(fs):
  at=0xD2+13*i;frag=body[at:at+13]
  need(int(f["il_offset"],16)==at and frag.hex()==f["il_body_hex"],"source field IL slice "+f["name"])
  need(frag[:9]==prefix and struct.unpack_from("<I",frag,9)[0]==int(f["token"],16),"original source read/store operation "+f["name"])
  need(f["read_input_relative_offset"]==16+i,"postincrement source cursor offset "+f["name"])
  row=base.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))
  need((row[0],row[1],row[2])==(f["row_hex"],("SkillData",""),f["name"]),"original FieldDef "+f["name"])
 # Fully check both source branches, not merely their expected output or fixture values.
 split=d["split"];frag=bytes.fromhex(split["exact_source_hex"])
 need(body[0x147:0x17F]==frag and split["raw_input_relative_offset"]==25,"complete tenth byte plus cutoff source block")
 need(body[0x152:0x154].hex()=="1f32" and split["signed_compare_literal"]==50,"literal signed 50")
 need(body[0x154]==0x3c and 0x159+struct.unpack_from("<i",body,0x155)[0]==0x16d,"original bge branch target")
 need(body[0x168]==0x38 and 0x16d+struct.unpack_from("<i",body,0x169)[0]==0x17f,"original br branch target")
 need(body[0x15c:0x161].hex()=="7d6b7c0004" and body[0x163:0x168].hex()=="7d6c7c0004","below cutoff field assignments")
 need(body[0x16f:0x174].hex()=="7d6b7c0004" and body[0x17a:0x17f].hex()=="7d6c7c0004","at/above cutoff assignments")
 for f in split["fields"]:
  row=base.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))
  need((row[0],row[1],row[2])==(f["row_hex"],("SkillData",""),f["name"]),"original branch field "+f["name"])
 for n in range(256):
  below=(n,0) if n<50 else (0,n-50)
  need((n<50 and below[0]==n and below[1]==0) or (n>=50 and below[0]==0 and below[1]==n-50),"complete unsigned byte cutoff cases")
 return {"original_source":"DLL-001","method_il_sha256":m["code_sha256"],"straight_line_field_reads":len(fs),"first_relative_offset":16,"last_relative_offset":24,"split_relative_offset":25,"branch_cutoff":50,"source_export_admitted":False}
def main():
 p=argparse.ArgumentParser();p.add_argument("--dll",required=True);a=p.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_ATTACK_BYTE_RUN_V1" and w["source_ids"]==["DLL-001"],"witness source identity")
  print(json.dumps(verify(a.dll,w),sort_keys=True,indent=2))
  print("PROVE_SKILL_DATA_MAN_RSF_ATTACK_BYTE_RUN: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_ATTACK_BYTE_RUN: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
