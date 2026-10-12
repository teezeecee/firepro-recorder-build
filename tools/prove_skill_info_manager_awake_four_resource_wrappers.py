#!/usr/bin/env python3
"""FACT-0293 original DLL-only Awake and four skill resource wrapper source proof."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_awake_four_resource_wrappers.summary.json"
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def mref(pe,s,b,z,o,sb,bb,t):
 p=o[10]+((t&0xffffff)-1)*z[10];raw=pe[p:p+z[10]]
 coded,p=base.rd(pe,p,z[10]-s-b);ni,p=base.rd(pe,p,s);bi,p=base.rd(pe,p,b)
 return raw.hex(),coded,base.s_at(pe,sb,ni),base.blob(pe,bb,bi).hex()
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original matching retail DLL")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 need(d["owner"]=="SkillInfoManager" and len(d["methods"])==5,"original five-method coverage")
 actual={}
 for m in d["methods"]:
  tok=int(m["token"],16);x=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok);body=x[9]
  need((x[0],x[1],x[4],x[5],x[7])==(m["row_hex"],int(m["rva"],16),m["name"],m["signature_hex"],("SkillInfoManager","")),"original source MethodDef "+m["token"])
  need(pe[base.off(ss,x[1]):x[8]].hex()==m["header_hex"],"method header "+m["name"])
  need((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["il_hex"],m["code_sha256"]),"original full IL "+m["name"])
  actual[tok]=body
 need(sum(len(x) for x in actual.values())==300 and len(actual[0x0600114A])==64 and all(len(actual[int(x["token"],16)])==59 for x in d["methods"][1:]),"300 bytes of exact source method bodies")
 for key,field in d["raw_fielddefs"].items():
  row,owner,name,sig=base.field(pe,s,b,z,o,sb,bb,fm,int(key,16))
  need((row,owner,name,sig)==(field["row"],("SkillInfoManager",""),field["name"],field["sig"]),"original source FieldDef "+key)
  at=int(field["ins"],16);expect=(b"\x80" if field["name"]=="inst" else b"\x7d")+struct.pack("<I",int(key,16))
  need(actual[0x0600114A][at:at+5]==expect,"original Awake field write "+key)
 for key,ref in d["raw_memberrefs"].items():
  need(mref(pe,s,b,z,o,sb,bb,int(key,16))==(ref["row"],int(ref["class_coded"],16),ref["name"],ref["sig"]),"original source MemberRef "+key)
 awake=actual[0x0600114A]
 for site in d["awake_ctor_sites"]:
  at=int(site["il"],16);need(awake[at:at+5]==b"\x73"+struct.pack("<I",int(site["target"],16)),"original container constructor "+site["il"])
 need(len(d["awake_method_calls"])==4,"four original Awake parser wrapper calls")
 for site,m in zip(d["awake_method_calls"],d["methods"][1:]):
  at=int(site["call_il"],16)
  need(awake[at:at+5]==b"\x28"+struct.pack("<I",int(m["token"],16)) and site["target"]==m["token"],"source Awake wrapper call "+m["name"])
 t=d["type_ref"];rid=int(t["token"],16)&0xffffff;p=o[1]+(rid-1)*z[1]
 row=pe[p:p+z[1]];scope,p=base.rd(pe,p,z[1]-2*s);ni,p=base.rd(pe,p,s);nsi,p=base.rd(pe,p,s)
 need((row.hex(),scope,base.s_at(pe,sb,ni),base.s_at(pe,sb,nsi))==(t["row_hex"],int(t["resolution_scope_coded"],16),t["name"],t["namespace"]),"original UnityEngine.TextAsset type")
 sites=d["wrapper_sites"]
 expect_calls=[("time_start_il",0x28,0x0A00055A),("load_il",0x28,0x0A0006DA),("get_text_il",0x6f,0x0A0006DB),("string_reader_ctor_il",0x73,0x0A0006DC),("unload_il",0x28,0x0A0006DF),("time_end_il",0x28,0x0A00055A)]
 for m in d["methods"][1:]:
  body=actual[int(m["token"],16)];u=int(m["user_string_token"],16);raw=base.blob(pe,st["#US"][0],u&0xffffff)
  need(raw[:-1].decode("utf-16le")==m["resource_name"] and body[:5]==b"\x72"+struct.pack("<I",u),"original #US resource string "+m["name"])
  need(body[int(sites["text_asset_cast_il"],16):int(sites["text_asset_cast_il"],16)+5]==b"\x75"+struct.pack("<I",int(t["token"],16)),"original TextAsset isinst "+m["name"])
  for key,opcode,target in expect_calls:
   at=int(sites[key],16);need(body[at:at+5]==bytes([opcode])+struct.pack("<I",target),"original wrapper instruction "+key+" "+m["name"])
  at=int(sites["internal_parser_il"],16);need(body[at:at+5]==b"\x28"+struct.pack("<I",int(m["internal_parser_token"],16)),"original private parser call "+m["name"])
 need(len(d["internal_parsers"])==4,"original distinct parser count")
 for parser in d["internal_parsers"]:
  x=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(parser["token"],16))
  need((x[0],x[4],x[5],x[7],len(x[9]),hashlib.sha256(x[9]).hexdigest())==(parser["method_row_hex"],parser["name"],parser["signature_hex"],("SkillInfoManager",""),parser["code_bytes"],parser["code_sha256"]),"original parser MethodDef identity "+parser["name"])
 need([m["resource_name"] for m in d["methods"][1:]]==["DataBase/SkillParam","DataBase/SkillInfo","DataBase/StorySkillUnlock","DataBase/SkillParam_Reversal"],"four original resources in Awake call order")
 return {"fact_id":"FACT-0293","source":"DLL-001","method_count":5,"source_method_bytes":300,"resources":[m["resource_name"] for m in d["methods"][1:]],"original_resource_payloads":"OPEN"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));need(w["dataset_id"]=="DLL_SKILL_INFO_MANAGER_AWAKE_AND_FOUR_RESOURCE_WRAPPERS_V1" and w["source_ids"]==["DLL-001"],"witness provenance")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_AWAKE_FOUR_RESOURCE_WRAPPERS: PASS");return 0
 except Exception as e:print("PROVE_SKILL_INFO_MANAGER_AWAKE_FOUR_RESOURCE_WRAPPERS: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
