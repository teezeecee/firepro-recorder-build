#!/usr/bin/env python3
"""FACT-0269 exact original-DLL IL window, metadata and four branch replay."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_attack_defence_flags.summary.json"
def need(v,msg):
 if not v:raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];win=d["source_window"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"retail DLL source identity")
 ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F)
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef")
 code=md[9]
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"] and len(code)==m["code_size"] and hashlib.sha256(code).hexdigest()==m["code_sha256"],"full parser original IL")
 lo=int(win["begin_il"],16);hi=int(win["end_exclusive_il"],16)
 need(hi-lo==win["byte_count"]==189 and hashlib.sha256(code[lo:hi]).hexdigest()==win["sha256"],"complete scoped original IL window")
 read=bytes.fromhex(win["read_sequence_hex"]);need(len(read)==9,"read token length")
 sites=[int(win[k],16) for k in ("first_read_il","second_read_il","third_read_il")]
 need(sites==[0x17F,0x1A3,0x1C7] and win["original_arg2_relative_positions"]==[26,27,28],"source read site offsets")
 for at in sites:need(code[at:at+9]==read,"source old-cursor ldelem.u1 at "+hex(at))
 # Retain original byte, high nibble masks (0xf0 >>4) and low nibble (0x0f), plus original stfld tokens.
 for i,(at_hi,at_lo) in enumerate([(0x188,0x198),(0x1AC,0x1BC)]):
  hi_prefix=bytes.fromhex(win["nibble_high_opcode_prefix_hex"])
  lo_prefix=bytes.fromhex(win["nibble_low_opcode_prefix_hex"])
  tok_hi=int(d["original_fields"][2*i]["token"],16);tok_lo=int(d["original_fields"][2*i+1]["token"],16)
  need(code[at_hi:at_hi+len(hi_prefix)+4]==hi_prefix+struct.pack("<I",tok_hi),"original high nibble store")
  need(code[at_lo:at_lo+len(lo_prefix)+4]==lo_prefix+struct.pack("<I",tok_lo),"original low nibble store")
 for f in d["original_fields"]:
  row=base.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))
  need((row[0],row[1],row[2])==(f["row_hex"],("SkillData",""),f["name"]),"original FieldDef "+f["name"])
 f=d["flag_field"];row=base.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))
 need((row[0],row[1],row[2])==(f["row_hex"],("SkillData",""),f["name"]),"original flags FieldDef")
 opcodes={1:0x17,2:0x18,4:0x1a,8:0x1e}
 for i,switch in enumerate(d["bit_tests"]):
  mask=switch["mask"];bit=switch["or_bit"];block=0x1d0+i*27
  need(int(switch["block_il"],16)==block and int(switch["branch_il"],16)==block+4 and int(switch["skip_to_il"],16)==block+27,"original switch location")
  expected=bytes([0x11,0x04,opcodes[mask],0x5f,0x39])+struct.pack("<i",18)+bytes.fromhex("07257b557c000420")+struct.pack("<i",bit)+bytes.fromhex("607d557c0004")
  need(code[block:block+27]==expected and block+9+struct.unpack_from("<i",code,block+5)[0]==block+27,"original conditional flags OR")
 # Test each low nibble combination against the four independent branch conditions.
 for x in range(256):
  v=0
  for test in d["bit_tests"]:
   if x&test["mask"]:v|=test["or_bit"]
  need(v==((x&0x0f)<<9),"bit-flag source correspondence")
 return {"source":"DLL-001","original_method_sha256":m["code_sha256"],"source_window_sha256":win["sha256"],"four_original_fields":True,"independent_flag_tests":4,"canonical_resource_verified":False}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);a=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_ATTACK_DEFENCE_PARAM_FLAGS_V1" and w["source_ids"]==["DLL-001"],"witness scope")
  print(json.dumps(verify(a.dll,w),indent=2,sort_keys=True));print("PROVE_SKILL_DATA_MAN_RSF_ATTACK_DEFENCE_FLAGS: PASS");return 0
 except Exception as err:
  print("PROVE_SKILL_DATA_MAN_RSF_ATTACK_DEFENCE_FLAGS: FAIL",err);return 1
if __name__=="__main__":raise SystemExit(main())
