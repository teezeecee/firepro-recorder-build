#!/usr/bin/env python3
"""FACT-0297: verify complete original retail Parse_Num source, exception handler, and 18 caller sites."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_num_source.summary.json"
def check(v,msg):
 if not v:raise AssertionError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();src=w["dll"];m=w["method"]
 check((len(pe),hashlib.sha256(pe).hexdigest())==(src["size_bytes"],src["sha256"]),"original raw DLL identity")
 ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
 s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
 sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
 node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16))
 body=node[9]
 check((node[0],node[1],node[4],node[5],node[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"MethodDef original identity")
 check(pe[p.off(ss,node[1]):node[8]].hex()==m["header"],"fat method header source")
 check((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["il_hex"],m["code_sha256"]),"complete original IL body")
 for x in w["members"]:
  tok=int(x["token"],16);a=x["site"]
  ro=o[10]+((tok&0xffffff)-1)*z[10];raw=pe[ro:ro+z[10]]
  coded,ptr=p.rd(pe,ro,z[10]-s-b);ni,ptr=p.rd(pe,ptr,s);si,ptr=p.rd(pe,ptr,b)
  check((raw.hex(),p.s_at(pe,sb,ni),p.blob(pe,bb,si).hex())==(x["row"],x["name"],x["signature"]),"original MemberRef row/name/signature "+x["token"])
  check(body[a:a+5]==bytes([0x28])+struct.pack("<I",tok),"original source call operand "+x["token"])
 for x in w["branch_flow"]:
  at=x["site"];rel=struct.unpack_from("<i",body,at+1)[0]
  check((body[at],rel,at+5+rel)==(int(x["opcode"],16),x["rel"],x["target"]),"original branch/leave at "+str(at))
 flow=w["source_semantics"]
 for a,b0 in (("is_null_or_empty_returns_zero","162a"),("exception_handler_return_zero","26160bdd"),("final_return","072a")):
  sl=flow[a];check(body[sl[0]:sl[-1]+1].hex()==b0,"source return sequence "+a)
 check(body.count(bytes([0x02]))>=2 and body[0]==body[13]==0x02,"first argument source loads")
 check(body[-1]==0x2a,"original final return")
 eh=w["exception_section"];al=(node[8]+len(body)+3)&~3
 check(pe[al:al+16].hex()==eh["source_hex"],"original EH clause exact bytes")
 check((pe[al],pe[al+1])==(1,16),"original small EH header")
 check((struct.unpack_from("<H",pe,al+4)[0],struct.unpack_from("<H",pe,al+6)[0],pe[al+8],struct.unpack_from("<H",pe,al+9)[0],pe[al+11],struct.unpack_from("<I",pe,al+12)[0])==(eh["clause_flags"],eh["try_offset"],eh["try_length"],eh["handler_offset"],eh["handler_length"],int(eh["catch_type_token"],16)),"source catch range/type")
 tok=int(eh["catch_type_token"],16);t=o[1]+((tok&0xffffff)-1)*z[1]
 row=pe[t:t+z[1]];rt,at=p.rd(pe,t,z[1]-2*s);ni,at=p.rd(pe,at,s);ns,at=p.rd(pe,at,s)
 check((row.hex(),p.s_at(pe,sb,ni),p.s_at(pe,sb,ns))==(eh["catch_typeref_row"],eh["catch_name"],eh["catch_namespace"]),"original catch TypeRef identity")
 parent=w["parent"];c=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(parent["token"],16));cb=c[9]
 check((len(cb),hashlib.sha256(cb).hexdigest())==(parent["size"],parent["sha256"]),"exact parent source identity")
 pat=bytes([0x28])+struct.pack("<I",int(m["token"],16))
 sites=[a for a in range(len(cb)-4) if cb[a:a+5]==pat]
 check(sites==parent["call_sites"] and len(sites)==18,"all 18 original caller sites")
 return {"fact":"FACT-0297","original_DLL":"PASS","IL_sha":m["code_sha256"],"calls_from_parent":len(sites),"authored_resources":"OPEN"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  check((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_NUM_SOURCE_V1",["DLL-001"]),"source witness identity")
  print(json.dumps(verify(args.dll,w),sort_keys=True))
  print("PROVE_SKILL_INFO_MANAGER_PARSE_NUM_SOURCE: PASS");return 0
 except Exception as exc:
  print("PROVE_SKILL_INFO_MANAGER_PARSE_NUM_SOURCE: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
