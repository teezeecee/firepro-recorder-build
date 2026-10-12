#!/usr/bin/env python3
"""FACT-0289 exact original matching retail DLL-only SkillInfoManager.GetSkillInfo proof."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_get_skill_info_key_lookup.summary.json"
IL="027bda0e0004036f5207000a3a02000000142a027bda0e0004036f5307000a2a"
def need(x,m):
 if not x: raise RuntimeError(m)
def memberref(pe,s,b,z,o,sb,bb,tok):
 rid=tok&0xffffff;p=o[10]+(rid-1)*z[10];raw=pe[p:p+z[10]]
 cls,p=base.rd(pe,p,z[10]-s-b);ni,p=base.rd(pe,p,s);si,p=base.rd(pe,p,b)
 return raw.hex(),cls,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex()
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original matching retail DLL size/hash")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 field_owners,method_owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,method_owners,0x06001164);body=md[9]
 need((md[0],md[1],md[4],md[5],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],m["signature_hex"],(m["owner"],"")),"original method metadata")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"]=="82","original tiny header")
 need((len(body),hashlib.sha256(body).hexdigest(),body.hex())==(m["code_bytes"],m["code_sha256"],m["il_hex"])==(32,"20b9e57db76492a26682a8438d6b177137717b54048168d56fa33ab8505032bd",IL),"full original 32-byte IL")
 expected=[("check_key_exists",0,12),("branch_and_null_exit",12,19),("lookup_and_return",19,32)]
 need(len(m["segments"])==len(expected),"source segment coverage count")
 for seg,(name,lo,hi) in zip(m["segments"],expected):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,lo,hi,body[lo:hi].hex()),"original IL source segment "+name)
 f=d["field"]
 need((f["token"],f["owner"],f["name"],f["metadata_row_hex"],f["signature_hex"])==("0x04000EDA","SkillInfoManager","skillInfoList","0600c74c0100250c0000","061512590211a9dc1286f8"),"FieldDef witness")
 need(base.field(pe,s,b,z,o,sb,bb,field_owners,0x04000EDA)==(f["metadata_row_hex"],(f["owner"],""),f["name"],f["signature_hex"]),"original raw FieldDef metadata")
 expected_refs={"0x0A000752":("ContainsKey","dc070000395e0600274d0000",2012,"2001021300",0x0007),"0x0A000753":("get_Item","dc0700001b51060032570000",2012,"200113011300",0x001a)}
 need(set(d["memberrefs"])==set(expected_refs),"original MemberRef identity set")
 for key,(name,row,cls,sig,posi) in expected_refs.items():
  a=d["memberrefs"][key]
  need((a["token"],a["name"],a["metadata_row_hex"],int(a["class_coded"],16),a["signature_hex"],int(a["callvirt_il"],16))==(key,name,row,cls,sig,posi),"MemberRef witness "+key)
  need(memberref(pe,s,b,z,o,sb,bb,int(key,16))==(row,cls,name,sig),"original raw MemberRef "+key)
  need(body[posi:posi+5]==b"\x6f"+struct.pack("<I",int(key,16)),"original source callvirt "+key)
 branch=d["branch"]
 need((branch["opcode"],branch["il"],branch["rel_s32"],branch["target_il"],branch["not_found_source_bytes"],branch["not_found_il"])==("0x3A","0x000C",2,"0x0013","142a","0x0011"),"branch and null witness")
 need(body[12]==0x3a and struct.unpack_from("<i",body,13)[0]==2 and 17+2==19,"original brtrue target")
 need(body[17:19]==bytes.fromhex("142a") and body[-1]==0x2a,"original null versus normal return")
 p=d["parent_call"]
 need((p["owner"],p["name"],p["token"],p["body_sha256"],p["call_il"],p["call_hex"],p["target_token"])==("SkillDataMan","LoadAdditionalAnimationData","0x0600525B","f5966ee12b5c4065dcef8f0f00c3832f13a0a600a5914a2452c1f4e116f3506e","0x0041","6f64110006","0x06001164"),"parent witness")
 parent=base.method(pe,ss,s,b,ix,z,o,sb,bb,method_owners,0x0600525B)
 need(hashlib.sha256(parent[9]).hexdigest()==p["body_sha256"] and parent[9][0x41:0x46]==bytes.fromhex(p["call_hex"]),"original parent source call")
 return {"fact_id":"FACT-0289","source":"DLL-001","method_sha256":m["code_sha256"],"parent_call":"SkillDataMan.LoadAdditionalAnimationData+0x0041","authored_skill_records":"OPEN"}
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--dll",required=True);args=parser.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_INFO_MANAGER_GET_SKILL_INFO_KEY_LOOKUP_V1" and w["source_ids"]==["DLL-001"],"original witness source id")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_INFO_MANAGER_GET_SKILL_INFO_KEY_LOOKUP: PASS")
  return 0
 except Exception as e:
  print("PROVE_SKILL_INFO_MANAGER_GET_SKILL_INFO_KEY_LOOKUP: FAIL",str(e))
  return 1
if __name__=="__main__":raise SystemExit(main())
