#!/usr/bin/env python3
"""FACT-0294 original matching DLL source checks: reversal record parser loop."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/skill_info_manager_reversal_param_parser_loop.summary.json"
def check(v,msg):
 if not v:raise RuntimeError(msg)
def member(pe,s,b,z,o,sb,bb,t):
 pos=o[10]+((t&0xffffff)-1)*z[10];raw=pe[pos:pos+z[10]]
 code,pos=p.rd(pe,pos,z[10]-s-b);ni,pos=p.rd(pe,pos,s);bi,pos=p.rd(pe,pos,b)
 return raw.hex(),code,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex()
def typ(pe,s,z,o,sb,t):
 pos=o[1]+((t&0xffffff)-1)*z[1];raw=pe[pos:pos+z[1]]
 scope,pos=p.rd(pe,pos,z[1]-2*s);ni,pos=p.rd(pe,pos,s);ns,pos=p.rd(pe,pos,s)
 return raw.hex(),scope,p.s_at(pe,sb,ni),p.s_at(pe,sb,ns)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 check((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL size and SHA")
 ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
 s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
 md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06001152);body=md[9]
 check((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["sig"],(m["owner"],"")),"original MethodDef identity")
 check(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original method header")
 check((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["bytes"],m["il_hex"],m["sha256"]),"original 113-byte body")
 pos=0
 for x in m["segments"]:
  lo=int(x["start_il"],16);hi=int(x["end_exclusive_il"],16)
  check(lo==pos and body[lo:hi].hex()==x["hex"],"original contiguous source segment");pos=hi
 check(pos==len(body)==113,"complete IL segment coverage")
 for key,x in d["members"].items():
  t=int(key,16)
  check(member(pe,s,b,z,o,sb,bb,t)==(x["row"],x["coded"],x["name"],x["sig"]),"original MemberRef "+key)
  for site in x["sites"]:
   check(body[site:site+5]==b"\x6f"+struct.pack("<I",t),"MemberRef call operand "+key)
 for key,x in d["types"].items():
  t=int(key,16)
  check(typ(pe,s,z,o,sb,t)==(x["row"],x["scope"],x["name"],x["namespace"]),"original TypeRef "+key)
  check(body[x["site"]:x["site"]+5]==bytes([x["opcode"]])+struct.pack("<I",t),"original TypeRef instruction "+key)
 for br in d["jumps"]:
  a=br["at"];rel=struct.unpack_from("<i",body,a+1)[0]
  check((body[a],rel,a+5+rel)==(br["opcode"],br["rel"],br["target"]),"original branch at "+hex(a))
 for key,x in d["deps"].items():
  t=int(key,16);node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,t)
  check((node[0],node[4],node[7],len(node[9]),hashlib.sha256(node[9]).hexdigest())==(x["row"],x["name"],(x["owner"],""),x["bytes"],x["sha"]),"original called method "+key)
  if not x.get("callsite_parent"):
   check(body[x["site"]:x["site"]+5]==bytes([x["opcode"]])+struct.pack("<I",t),"original direct method call "+key)
  else:check(node[9][x["site"]:x["site"]+5]==b"\x28"+struct.pack("<I",int(m["token"],16)),"original wrapper call site")
 f=d["reversal_field"]
 check(p.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))==(f["row"],(f["owner"],""),f["name"],f["sig"]),"original reversal list FieldDef")
 check(body[f["site"]:f["site"]+5]==b"\x7b"+struct.pack("<I",int(f["token"],16)),"original list field load")
 u=d["user_string"];raw=p.blob(pe,st["#US"][0],int(u["token"],16)&0xffffff)
 check(raw.hex()==u["utf16le_marker_hex"] and raw[:-1].decode("utf-16le")==u["text"]=="end","source end literal bytes")
 check(body[u["site"]:u["site"]+5]==b"\x72"+struct.pack("<I",int(u["token"],16)),"original ldstr end")
 v=d["delimiter"]
 check(v["value"]==44 and body[v["site"]:v["site"]+2].hex()==v["hex"]=="1f2c" and v["char_array_length"]==1,"original comma literal")
 check(body[13]==body[20]==0x26 and body[112]==0x2a,"source skipped headers and final ret")
 return {"fact":"FACT-0294","original_DLL":"PASS","IL_sha":m["sha256"],"record_parser_internal":"OPEN"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));check(w["dataset_id"]=="DLL_SKILL_INFO_MANAGER_REVERSAL_PARAM_PARSER_LOOP_V1" and w["source_ids"]==["DLL-001"],"witness identity")
  print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_REVERSAL_PARAM_PARSER_LOOP: PASS");return 0
 except Exception as exc:print("PROVE_SKILL_INFO_MANAGER_REVERSAL_PARAM_PARSER_LOOP: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
