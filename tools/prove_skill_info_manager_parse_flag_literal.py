#!/usr/bin/env python3
"""FACT-0296: verify exact original Parse_Flag method, literal and parent calls."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_flag_literal.summary.json"
def check(x,msg):
 if not x: raise AssertionError(msg)
def verify(path,w):
 d=Path(path).read_bytes();ref=w["dll"];m=w["method"]
 check((len(d),hashlib.sha256(d).hexdigest())==(ref["size_bytes"],ref["sha256"]),"original DLL identity")
 sec,q=p.secs(d);streams,hs,rows,pos=p.mdstreams(d,sec,q)
 s,b,ix,z,o=p.tables(d,streams,hs,rows,pos)
 sb=streams["#Strings"][0]; bb=streams["#Blob"][0]
 fm,owners=p.owner_maps(d,rows,s,ix,z,o,sb)
 got=p.method(d,sec,s,b,ix,z,o,sb,bb,owners,0x06001159)
 body=got[9]
 check((got[0],got[1],got[4],got[5],got[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"MethodDef original identity")
 check(d[p.off(sec,got[1]):got[8]].hex()==m["tiny_header"],"tiny header")
 check((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["il_hex"],m["code_sha256"]),"complete original IL")
 for node in w["members"]:
  t=int(node["token"],16); pp=o[10]+((t&0xffffff)-1)*z[10]
  raw=d[pp:pp+z[10]];coded,sp=p.rd(d,pp,z[10]-s-b);name_index,sp=p.rd(d,sp,s);sig_index,sp=p.rd(d,sp,b)
  check((raw.hex(),p.s_at(d,sb,name_index),p.blob(d,bb,sig_index).hex())==(node["row"],node["name"],node["signature"]),"original MemberRef identity "+node["token"])
  opcode=0x28 if node["opcode"]=="call" else 0x6f
  check(body[node["il_offset"]:node["il_offset"]+5]==bytes([opcode])+struct.pack("<I",t),"original call instruction "+node["token"])
 for x in w["branches"]:
  at=x["offset"];op=body[at];rel=struct.unpack_from("<i",body,at+1)[0]
  check((op,rel,at+5+rel)==(int(x["opcode"],16),x["rel"],x["target"]),"original branch "+str(at))
 t=int(w["literal"]["token"],16);at=w["literal"]["il_offset"]
 check(body[at:at+5]==bytes([0x72])+struct.pack("<I",t),"original ldstr operand")
 raw=p.blob(d,streams["#US"][0],t&0xffffff)
 check((raw.hex(),raw[:-1].decode("utf-16le"))==(w["literal"]["unpacked_payload_hex"],w["literal"]["source_text"]),"source original literal '0'")
 heap_at=streams["#US"][0]+(t&0xffffff)
 check(d[heap_at:heap_at+4].hex()==w["literal"]["user_string_heap_record_hex"],"original US heap encoding")
 check(body[11:13]==bytes([0x16,0x2a]) and body[29:31]==bytes([0x17,0x2a]) and body[31:33]==bytes([0x16,0x2a]),"Boolean branch return sequences")
 parent=w["parent"];pm=p.method(d,sec,s,b,ix,z,o,sb,bb,owners,int(parent["token"],16));pb=pm[9]
 check((len(pb),hashlib.sha256(pb).hexdigest())==(parent["code_bytes"],parent["code_sha256"]),"exact source parent")
 pats=[i for i in range(len(pb)-4) if pb[i:i+5]==bytes([0x28])+struct.pack("<I",0x06001159)]
 check(pats==parent["call_sites"] and len(pats)==17,"all 17 original direct parent sites")
 return {"fact":"FACT-0296","original_dll":"PASS","method_bytes":len(body),"parent_direct_calls":len(pats),"literal":"0","runtime_eligible":False}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  check((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_FLAG_LITERAL_V1",["DLL-001"]),"witness identity")
  print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_PARSE_FLAG_LITERAL: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_INFO_MANAGER_PARSE_FLAG_LITERAL: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
