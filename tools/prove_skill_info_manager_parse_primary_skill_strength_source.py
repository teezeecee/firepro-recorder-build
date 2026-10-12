#!/usr/bin/env python3
"""FACT-0299 exact original Parse_PrimarySkillStrength string-literal ordinal mapping."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_primary_skill_strength_source.summary.json"
def check(v,context):
 if not v:raise AssertionError(context)
def verify(path,w):
 raw=Path(path).read_bytes();dll=w["dll"];m=w["method"]
 check((len(raw),hashlib.sha256(raw).hexdigest())==(dll["size_bytes"],dll["sha256"]),"original DLL identity")
 ss,q=p.secs(raw);st,hs,rows,tab=p.mdstreams(raw,ss,q);s,b,ix,z,o=p.tables(raw,st,hs,rows,tab)
 sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=p.owner_maps(raw,rows,s,ix,z,o,sb)
 method=p.method(raw,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=method[9]
 check((method[0],method[1],method[4],method[5],method[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef metadata")
 check(raw[p.off(ss,method[1]):method[8]].hex()==m["header"],"original method header")
 check((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["code_bytes"],m["il_hex"],m["code_sha256"]),"complete original 69-byte source IL")
 check(m["has_exception_section"] is False and (int.from_bytes(bytes.fromhex(m["header"])[:2],"little")&8)==0,"no original exception clause")
 for x in w["memberrefs"]:
  t=int(x["token"],16);row=o[10]+((t&0xffffff)-1)*z[10];re=raw[row:row+z[10]]
  coded,ptr=p.rd(raw,row,z[10]-s-b);ni,ptr=p.rd(raw,ptr,s);si,ptr=p.rd(raw,ptr,b)
  check((re.hex(),p.s_at(raw,sb,ni),p.blob(raw,bb,si).hex())==(x["row"],x["name"],x["signature"]),"original memberref metadata "+x["token"])
  op=0x28 if x["opcode"]=="call" else 0x6f
  for site in x["call_sites"]:check(il[site:site+5]==bytes([op])+struct.pack("<I",t),"original instruction "+str(site))
 empty=w["empty_check"];a=empty["branch_site"];d=struct.unpack_from("<i",il,a+1)[0]
 check((il[a],d,a+5+d)==(int(empty["branch_opcode"],16),2,empty["false_target"]),"original null check branch")
 check(il[empty["return_site"]:empty["return_site"]+2]==bytes([0x16,0x2a]),"original empty return zero")
 for x in w["literal_cases"]:
  t=int(x["token"],16);a=x["ldstr_site"];raw_us=st["#US"][0]+(t&0xffffff)
  check(il[a:a+5]==bytes([0x72])+struct.pack("<I",t),"source ldstr token "+x["literal"])
  check(raw[raw_us:raw_us+4].hex()==x["heap_record"],"source literal heap record "+x["literal"])
  check(raw[raw_us+1:raw_us+3].decode("utf-16-le")==x["literal"],"source literal value "+x["literal"])
  a=x["branch_site"];d=struct.unpack_from("<i",il,a+1)[0]
  check((il[a],d,a+5+d)==(0x39,2,x["false_target"]),"source branch target "+x["literal"])
  a=x["return_site"];code=(0x16+x["return_ordinal"])
  check(il[a:a+2]==bytes([code,0x2a]),"source returned ordinal "+x["literal"])
 default=w["default_return"];check(il[default["site"]:default["site"]+2]==bytes([0x16,0x2a]),"source default return zero")
 parent=w["parent"];pm=p.method(raw,ss,s,b,ix,z,o,sb,bb,owners,int(parent["token"],16));pb=pm[9]
 check((len(pb),hashlib.sha256(pb).hexdigest())==(parent["code_bytes"],parent["code_sha256"]),"exact original caller identity")
 pat=bytes([0x28])+struct.pack("<I",int(m["token"],16));calls=[i for i in range(len(pb)-4) if pb[i:i+5]==pat]
 check(calls==parent["direct_call_sites"]==[210],"exact original parent callsites")
 return {"fact":"FACT-0299","original_dll":"PASS","source_literals":{"S":0,"M":1,"L":2},"caller_sites":calls,"runtime_eligible":False}
def main():
 args=argparse.ArgumentParser();args.add_argument("--dll",required=True);a=args.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));check((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_PRIMARY_SKILL_STRENGTH_SOURCE_V1",["DLL-001"]),"source witness identity")
  print(json.dumps(verify(a.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_PARSE_PRIMARY_SKILL_STRENGTH_SOURCE: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_INFO_MANAGER_PARSE_PRIMARY_SKILL_STRENGTH_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
