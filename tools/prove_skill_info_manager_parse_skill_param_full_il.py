#!/usr/bin/env python3
"""FACT-0295 raw-original DLL verifier. Never treat metadata names as authored resource rows."""
import argparse, collections, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_skill_param_full_il.summary.json"
def check(cond,msg):
 if not cond: raise AssertionError(msg)
def verify(path,w):
 pe=Path(path).read_bytes(); d=w["dll"]; m=w["method"]
 check((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching source DLL")
 ss,q=p.secs(pe); st,hs,rows,pos=p.mdstreams(pe,ss,q)
 s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
 sb=st["#Strings"][0]; bb=st["#Blob"][0]
 fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
 md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06001153); body=md[9]
 check((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original method metadata")
 check(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original method header")
 check((len(body),hashlib.sha256(body).hexdigest())==(m["bytes"],m["sha256"]),"complete original source IL")
 counts={}
 for key,n in w["calls"].items():
  t=int(key,16); pat=bytes([0x28])+struct.pack("<I",t)
  hits=sum(body[i:i+5]==pat for i in range(len(body)-4))
  check(hits==n,"original call operand "+key);counts[key]=hits
 check(sum(counts.values())==w["counts"]["direct_calls"],"full source calls")
 for x in w["guards"]:
  t=int(x["token"],16);a=x["site"]
  f=p.field(pe,s,b,z,o,sb,bb,fm,t)
  check((f[1],f[2])==(("SkillInfo",""),x["name"]),"original FieldDef name/owner "+x["token"])
  check(body[a:a+5]==bytes([0x7d])+struct.pack("<I",t),"original source field-write site "+x["token"])
 for key,x in w["memberrefs"].items():
  t=int(key,16);a=x["site"]
  pp=o[10]+((t&0xffffff)-1)*z[10];raw=pe[pp:pp+z[10]]
  check(raw.hex()==x["row"],"original member row "+key)
  check(body[a:a+5]==bytes([0x28])+struct.pack("<I",t),"original member call site "+key)
 for key,sha in w["child_hashes"].items():
  md2=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(key,16))
  check(hashlib.sha256(md2[9]).hexdigest()==sha,"helper method original source "+key)
 par=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(w["source_parent"]["token"],16))[9]
 check(par[w["source_parent"]["direct_call_il"]:w["source_parent"]["direct_call_il"]+5]==bytes([0x28])+struct.pack("<I",0x06001153),"original FACT-0294 caller")
 end=md[8]+len(body)
 check(pe[end:end+16].hex()==w["eh"]["raw"],"original small EH clause")
 for op,table,expect in ((0x7d,0x04,46),(0x7b,0x04,20),(0x72,0x70,35)):
  check(sum(body[i]==op and body[i+4]==table for i in range(len(body)-4))==expect,"full source token opcode count "+hex(op))
 check(body[-1]==0x2a,"source ret")
 return {"fact":"FACT-0295","original_dll":"PASS","code_bytes":len(body),"code_sha256":m["sha256"],"original_source_calls":sum(counts.values()),"loaded_resource_data":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));check(w["dataset_id"]=="DLL_SKILL_INFO_MANAGER_PARSE_SKILL_PARAM_FULL_IL_V1","witness ID")
  print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_PARSE_SKILL_PARAM_FULL_IL: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_INFO_MANAGER_PARSE_SKILL_PARAM_FULL_IL: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
