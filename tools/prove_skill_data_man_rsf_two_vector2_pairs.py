#!/usr/bin/env python3
"""FACT-0271: replay original retail DLL bytes and CLR constructor metadata."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_two_vector2_pairs.summary.json"
def need(v,msg):
 if not v:raise RuntimeError(msg)
def replay(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];v=d["window"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original SHA-pinned DLL identity")
 sec,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,sec,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 _,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,sec,s,b,ix,z,o,sb,bb,owners,0x0600525F)
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"source MethodDef")
 body=md[9]
 need(pe[base.off(sec,md[1]):md[8]].hex()==m["header_hex"] and len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"complete parser source")
 need(v["start_il"]=="0x029E" and v["end_exclusive_il"]=="0x02DE" and v["length_bytes"]==64,"witness IL window")
 window=body[0x29e:0x2de]
 need(len(window)==64 and hashlib.sha256(window).hexdigest()==v["source_sha256"],"original 64-byte window SHA")
 first=v["first_pair"];second=v["second_pair"]
 signed=bytes.fromhex(first["source_hex"]);unsigned=bytes.fromhex(second["source_hex"])
 need(len(signed)==33 and len(unsigned)==31 and window==signed+unsigned,"both exact original constructor blocks")
 # Decode byte consumption in original IL, not from an exported record or inferred move.
 load=bytes.fromhex("03082517580c91")
 need(signed[0:7]==load and signed[10:17]==load,"signed pair unsigned-byte loads")
 need(signed[7:10]==bytes.fromhex("671305") and signed[17:20]==bytes.fromhex("671306"),"first pair has explicit conv.i1 into locals 5 and 6")
 need(unsigned[0:9]==load+bytes.fromhex("1308") and unsigned[9:18]==load+bytes.fromhex("1309"),"second pair unsigned-byte loads omit conv.i1")
 need(signed[20:28]==bytes.fromhex("120711056b11066b") and unsigned[18:26]==bytes.fromhex("120a11086b11096b"),"float-converted local-address constructor arguments")
 call=bytes.fromhex("288800000a")
 need(signed[28:33]==call and unsigned[26:31]==call,"two original MemberRef calls")
 need((first["relative_input_bytes"],second["relative_input_bytes"])==([36,37],[38,39]),"source cursor continuity after FACT-0270")
 need((first["constructor_call_il"],second["constructor_call_il"])==("0x02BA","0x02D9"),"original IL call offsets")
 mr=v["constructor_memberref"];rid=int(mr["token"],16)&0xffffff
 pos=o[10]+(rid-1)*z[10];row=pe[pos:pos+z[10]]
 need(row.hex()==mr["row_hex"] and rid==136,"original MemberRef row")
 coded_size=z[10]-s-b
 coded,pos=base.rd(pe,pos,coded_size);ni,pos=base.rd(pe,pos,s);sig,_=base.rd(pe,pos,b)
 need(coded==(12<<3|1) and base.s_at(pe,sb,ni)==mr["name"]==".ctor" and base.blob(pe,bb,sig).hex()==mr["signature_hex"]=="2002010c0c","constructor class and signature")
 t=mr["type_ref_row_id"];where=o[1]+(t-1)*z[1]
 need((0x01000000|t)==int(mr["type_ref_token"],16) and pe[where:where+z[1]].hex()==mr["type_ref_row_hex"],"original TypeRef row")
 scope_size=z[1]-2*s
 nidx,pos=base.rd(pe,where+scope_size,s);nsidx,_=base.rd(pe,pos,s)
 need((base.s_at(pe,sb,nidx),base.s_at(pe,sb,nsidx))==(mr["type_name"],mr["type_namespace"])==("Vector2","UnityEngine"),"actual UnityEngine.Vector2 metadata")
 need(sum((((n+128)%256)-128)!=n for n in range(256))==128,"original conv.i1 signedness distinction")
 return {"source":"DLL-001","window_sha256":v["source_sha256"],"relative_bytes":[36,37,38,39],"first_pair_signed_int8":True,"second_pair_without_int8_sign_conversion":True,"constructor":"UnityEngine.Vector2::.ctor(float32,float32)","gameplay_meaning":"OPEN"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--dll",required=True);a=p.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_TWO_VECTOR2_SIGNED_UNSIGNED_PAIRS_V1" and w["source_ids"]==["DLL-001"],"witness identity")
  print(json.dumps(replay(a.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_TWO_VECTOR2_PAIRS: PASS");return 0
 except Exception as exc:
  print("PROVE_SKILL_DATA_MAN_RSF_TWO_VECTOR2_PAIRS: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
