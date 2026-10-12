#!/usr/bin/env python3
"""FACT-0291 original-DLL byte and FieldDef proof for SkillInfoManager.ApplySkillParam."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_apply_skill_param_transfers.summary.json"
M_SHA="49f3fdacd9378d68c7c474766af4ba146ebccc86a8acbb27e240f63353640291"
def need(x,s):
 if not x:raise RuntimeError(s)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original matching DLL SHA/size")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06001166);body=md[9]
 need((md[0],md[1],md[4],md[5],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],m["signature_hex"],(m["owner"],"")),"original MethodDef metadata")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original IL method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"])==(386,M_SHA),"complete original 386-byte IL SHA")
 segments=d["segments"];expected=[("get_skill_info_and_null_return",0,15),("name_copy_two_item_loop",15,49),("twenty_eight_skill_info_transfers",49,385),("method_return",385,386)]
 need(len(segments)==4,"source segment count")
 for g,(name,lo,hi) in zip(segments,expected):
  need((g["name"],int(g["start_il"],16),int(g["end_exclusive_il"],16),g["il_hex"],g["sha256"])==(name,lo,hi,body[lo:hi].hex(),hashlib.sha256(body[lo:hi]).hexdigest()),"source IL window "+name)
 need(b"".join(bytes.fromhex(x["il_hex"]) for x in segments)==body,"complete source method byte coverage")
 fs=d["fielddefs"];need(len(fs)==58,"58 original FieldDef identities")
 for key,x in fs.items():
  need(x["token"]==key and base.field(pe,s,b,z,o,sb,bb,fm,int(key,16))==(x["metadata_row_hex"],(x["owner"],""),x["name"],x["signature_hex"]),"original FieldDef "+key)
 pairs=d["transfer_pairs"];need(len(pairs)==28,"exact 28 direct copy pairs")
 last=49;seen=set()
 for p in pairs:
  lo=int(p["start_il"],16);hi=int(p["end_exclusive_il"],16);src=int(p["input_field"],16);dst=int(p["output_field"],16)
  need(lo==last and hi==lo+12,"exact contiguous 12-byte field block")
  seq=b"\x03\x06\x7b"+struct.pack("<I",src)+b"\x7d"+struct.pack("<I",dst)
  need(body[lo:hi]==seq and seq.hex()==p["il_hex"],"exact source ldfld/stfld instruction sequence "+p["field_name"])
  a=fs[p["input_field"]];b_=fs[p["output_field"]]
  need((a["owner"],b_["owner"],a["name"],b_["name"])==("SkillInfo","SkillData",p["field_name"],p["field_name"]),"source/dest field name and owner")
  need((src,dst) not in seen,"repeated field transfer");seen.add((src,dst));last=hi
 need(last==385 and body[385]==0x2a,"transfer stream reaches original ret")
 names=d["name_copy"]
 need((names["source_name_field"],names["destination_name_field"],names["loop_start_il"],names["loop_end_exclusive_il"],names["index_start"],names["index_bound"])==("0x04000EB5","0x04007C50","0x0016","0x0031",0,2),"original name-array copy loop")
 need(fs["0x04000EB5"]["name"]==fs["0x04007C50"]["name"]=="skillName","source and destination names")
 need(body[22:38].hex()==names["name_copy_body_hex"]=="037b507c000407067bb50e0004079aa2","source name transfer")
 need(body[15:22].hex()=="160b3814000000" and body[38:49].hex()=="0717580b07183fe5ffffff","index 0 and 1 array loop")
 br=d["branches"];spec=[("nonnull_gate",9,0x3a,1,15),("name_copy_initial_skip",17,0x38,20,42),("two_name_entries_loop",44,0x3f,-27,22)]
 need(len(br)==3,"three long branches")
 for x,(name,at,op,rel,target) in zip(br,spec):
  need((x["name"],int(x["il"],16),int(x["opcode"],16),x["rel_s32"],int(x["target_il"],16))==(name,at,op,rel,target),"branch witness "+name)
  need(body[at]==op and struct.unpack_from("<i",body,at+1)[0]==rel and at+5+rel==target,"original branch "+name)
 need(body[:8].hex()=="020428641100060a" and body[14]==0x2a,"original GetSkillInfo call and immediate null return")
 lookup=d["lookup_call"];need((lookup["methoddef"],lookup["name"],lookup["call_il"],lookup["call_hex"])==("0x06001164","GetSkillInfo","0x0002","2864110006"),"GetSkillInfo witness")
 dep=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06001164)
 need(dep[4]=="GetSkillInfo" and dep[7]==("SkillInfoManager","") and hashlib.sha256(dep[9]).hexdigest()==lookup["method_sha256"],"linked original GetSkillInfo")
 parent=d["parent_call"];need((parent["methoddef"],parent["name"],parent["call_il"],parent["call_hex"])==("0x0600525B","LoadAdditionalAnimationData","0x00BC","6f66110006"),"parent witness")
 pm=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525B)
 need(pm[4]=="LoadAdditionalAnimationData" and pm[7]==("SkillDataMan","") and hashlib.sha256(pm[9]).hexdigest()==parent["parent_sha256"] and pm[9][0xbc:0xc1].hex()==parent["call_hex"],"original caller")
 return {"fact_id":"FACT-0291","source":"DLL-001","method_sha256":M_SHA,"source_bytes":386,"fielddef_count":58,"direct_transfer_count":28,"name_array_copy_count_if_present":2,"authored_skill_table":"OPEN"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--dll",required=True);args=p.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));need(w["dataset_id"]=="DLL_SKILL_INFO_MANAGER_APPLY_SKILL_PARAM_TRANSFERS_V1" and w["source_ids"]==["DLL-001"],"witness ID")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_APPLY_SKILL_PARAM_TRANSFERS: PASS");return 0
 except Exception as exc:print("PROVE_SKILL_INFO_MANAGER_APPLY_SKILL_PARAM_TRANSFERS: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
