#!/usr/bin/env python3
"""FACT-0270: direct original-retail DLL replay of six bytes and flags OR."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_six_suicide_damage_bytes.summary.json"
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def verify(path,w):
 raw=Path(path).read_bytes();d=w["dll"];m=d["method"];win=d["window"]
 need(len(raw)==d["size_bytes"] and hashlib.sha256(raw).hexdigest()==d["sha256"],"original source DLL")
 sections,q=base.secs(raw);st,hs,rows,p=base.mdstreams(raw,sections,q)
 s,b,ix,z,o=base.tables(raw,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 field_owners,method_owners=base.owner_maps(raw,rows,s,ix,z,o,sb)
 method=base.method(raw,sections,s,b,ix,z,o,sb,bb,method_owners,0x0600525F)
 need((method[0],method[1],method[4],method[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef")
 il=method[9]
 need(raw[base.off(sections,method[1]):method[8]].hex()==m["header_hex"],"original method header")
 need(len(il)==m["il_bytes"] and hashlib.sha256(il).hexdigest()==m["il_sha256"],"full method SHA")
 start=int(win["start_il"],16);end=int(win["end_exclusive_il"],16)
 need((start,end,end-start)==(0x23c,0x29e,98) and hashlib.sha256(il[start:end]).hexdigest()==win["sha256"],"complete 98-byte IL window")
 fields=win["six_13_byte_field_reads"]
 need(len(fields)==6,"six fields")
 expected=bytes.fromhex(win["postincrement_read_opcode_prefix_hex"])
 need(expected==bytes.fromhex("0703082517580c917d"),"read opcode source sequence")
 for i,field in enumerate(fields):
  at=start+i*13;frag=il[at:at+13]
  need(int(field["source_il"],16)==at and field["relative_input_offset"]==29+i,"derived original old-cursor offset")
  need(frag==expected+struct.pack("<I",int(field["token"],16))==bytes.fromhex(field["source_hex"]),"raw stfld sequence "+field["name"])
  row=base.field(raw,s,b,z,o,sb,bb,field_owners,int(field["token"],16))
  need((row[0],row[1],row[2])==(field["row_hex"],("SkillData",""),field["name"]),"original FieldDef "+field["name"])
 fl=win["flags_read"]
 need(int(fl["il"],16)==start+6*13==0x28a and fl["relative_input_offset"]==35,"seventh original byte postincrement offset")
 frag=il[0x28a:0x29e]
 need(frag.hex()==fl["source_hex"] and len(frag)==20,"raw original field flags OR source")
 need(frag==bytes.fromhex("07257b")+struct.pack("<I",int(fl["flags_field_token"],16))+bytes.fromhex("03082517580c91607d")+struct.pack("<I",int(fl["flags_field_token"],16)),"original flags ldfld/read/or/stfld operation")
 frow=base.field(raw,s,b,z,o,sb,bb,field_owners,int(fl["flags_field_token"],16))
 need((frow[0],frow[1],frow[2])==(fl["flags_field_row_hex"],("SkillData",""),fl["flags_field_name"]),"original flags FieldDef")
 # Continuity with FACT-0269's four independent flags gates.
 need(il[0x225]==0x39 and 0x22A+struct.unpack_from("<i",il,0x226)[0]==start,"prior fourth brfalse join")
 need(il[0x22a:0x23c].hex()=="07257b557c00042000100000607d557c0004","prior bit8 true branch falls through")
 for old in [0,1,255,256,0x1000,0xffff]:
  for byte in range(256):need((old|byte)&~old==byte&~old,"flags raw OR all unsigned inputs")
 return {"source":"DLL-001","method_sha":m["il_sha256"],"window_sha":win["sha256"],"unconditional_field_writes":6,"old_cursor_offsets":[29,30,31,32,33,34,35],"original_binary_export_promoted":False}
def main():
 p=argparse.ArgumentParser();p.add_argument("--dll",required=True);args=p.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));need(w["source_ids"]==["DLL-001"] and w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_SIX_SUICIDE_DAMAGE_BYTES_AND_FLAGS_V1","witness scope")
  print(json.dumps(verify(args.dll,w),sort_keys=True,indent=2));print("PROVE_SKILL_DATA_MAN_RSF_SIX_SUICIDE_DAMAGE_BYTES: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_SIX_SUICIDE_DAMAGE_BYTES: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
