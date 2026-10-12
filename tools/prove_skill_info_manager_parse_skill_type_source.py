#!/usr/bin/env python3
"""FACT-0298: source-verify original Parse_SkillType full IL and format-check placement."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_skill_type_source.summary.json"
def check(v,label):
 if not v:raise AssertionError(label)
def verify(path,w):
 pe=Path(path).read_bytes();dll=w["dll"];m=w["method"]
 check((len(pe),hashlib.sha256(pe).hexdigest())==(dll["size_bytes"],dll["sha256"]),"original SHA-matched DLL identity")
 ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
 s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
 sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
 node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));body=node[9]
 check((node[0],node[1],node[4],node[5],node[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef token identity")
 check(pe[p.off(ss,node[1]):node[8]].hex()==m["header"],"original fat method header")
 check((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["il_hex"],m["code_sha256"]),"original complete 71-byte IL")
 for x in w["calls"]:
  tok=int(x["token"],16);a=x["site"];op=0x28 if x["opcode"]=="call" else 0x6f
  check(body[a:a+5]==bytes([op])+struct.pack("<I",tok),"original IL call at "+str(a))
  ro=o[10]+((tok&0xffffff)-1)*z[10];raw=pe[ro:ro+z[10]]
  coded,at=p.rd(pe,ro,z[10]-s-b);ni,at=p.rd(pe,at,s);si,at=p.rd(pe,at,b)
  check((raw.hex(),p.s_at(pe,sb,ni),p.blob(pe,bb,si).hex())==(x["row"],x["name"],x["signature"]),"original MemberRef "+x["token"])
 for x in w["branches"]:
  a=x["site"];v=struct.unpack_from("<i",body,a+1)[0]
  check((body[a],v,a+5+v)==(int(x["opcode"],16),x["relative"],x["target"]),"original branch/leave at "+str(a))
 lit=w["literal"];tok=int(lit["token"],16);a=lit["site"]
 check(body[a:a+5]==bytes([0x72])+struct.pack("<I",tok),"literal ldstr token")
 us=st["#US"][0]+(tok&0xffffff)
 check(pe[us:us+4].hex()==lit["user_string_heap_record_hex"],"original UserString heap literal")
 check(pe[us+1:us+3].decode("utf-16-le")==lit["text"],"original literal space")
 for arg in w["call_argument_windows"]:
  a=arg["call_site"];span=bytes.fromhex(arg["il_window_hex"])
  check(body[a-3:a+5]==span,"source Substring argument window "+str(a))
 flow=w["original_flow"]
 check(body[11:13]==bytes([0x16,0x2a]) and body[36:38]==bytes([0x16,0x2a]) and body[61:64]==bytes([0x26,0x16,0x0b]) and body[69:71]==bytes([0x07,0x2a]),"original return sequences")
 eh=w["exception_section"];start=(node[8]+len(body)+3)&~3;src=pe[start:start+16]
 check(src.hex()==eh["source_hex"] and (src[0],src[1])==(1,16),"original small EH header/bytes")
 check((struct.unpack_from("<H",src,4)[0],struct.unpack_from("<H",src,6)[0],src[8],struct.unpack_from("<H",src,9)[0],src[11],struct.unpack_from("<I",src,12)[0])==(eh["clause_flags"],eh["try_offset"],eh["try_length"],eh["handler_offset"],eh["handler_length"],int(eh["catch_type_token"],16)),"exact EH catch bounds")
 check(flow["parse_try_start"]==eh["try_offset"]==40 and 16<40,"first original substring outside catch")
 tok=int(eh["catch_type_token"],16);at=o[1]+((tok&0xffffff)-1)*z[1];raw=pe[at:at+z[1]]
 coded,x=p.rd(pe,at,z[1]-2*s);ni,x=p.rd(pe,x,s);ns,x=p.rd(pe,x,s)
 check((raw.hex(),p.s_at(pe,sb,ni),p.s_at(pe,sb,ns))==(eh["catch_typeref_row"],eh["catch_name"],eh["catch_namespace"]),"original catch TypeRef")
 parent=w["parent"];caller=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(parent["token"],16));cb=caller[9]
 check((len(cb),hashlib.sha256(cb).hexdigest())==(parent["code_bytes"],parent["code_sha256"]),"exact original caller")
 pat=bytes([0x28])+struct.pack("<I",int(m["token"],16));sites=[a for a in range(len(cb)-4) if cb[a:a+5]==pat]
 check(sites==parent["direct_call_sites"]==[170],"original direct caller site")
 return {"fact":"FACT-0298","status":"PASS","method_source_bytes":len(body),"direct_parent_calls":len(sites),"runtime_eligible":False}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  check((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_SKILL_TYPE_SOURCE_V1",["DLL-001"]),"source witness provenance")
  print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_PARSE_SKILL_TYPE_SOURCE: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_INFO_MANAGER_PARSE_SKILL_TYPE_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
