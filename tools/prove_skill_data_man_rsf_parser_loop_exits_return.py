#!/usr/bin/env python3
"""FACT-0286 exact source proof of original ParseRSFData MethodDef final IL suffix."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_parser_loop_exits_return.summary.json"
EXPECTED=[
 ("increment_inner_form_index_and_loop",0x069e,0x06b2,"110f1758130f110f110e7b937c00043fd9fdffff",0x06ad,-551,0x048b,"0x04007C93"),
 ("increment_outer_animation_index_and_loop",0x06b2,0x06c5,"110d1758130d110d077b547c00043feefcffff",0x06c0,-786,0x03b3,"0x04007C54"),
 ("return_local1",0x06c5,0x06c7,"072a",None,None,None,None)
]
FIELDS={
 "0x04007C93":("WrestlerAnmData","formNum","06000c75010001000000","0608"),
 "0x04007C54":("SkillData","anmNum","0600f472010001000000","0608")
}
def need(condition,message):
 if not condition: raise RuntimeError(message)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original matching DLL SHA and size")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 field_owners,method_owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,method_owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef metadata")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"complete original MethodDef IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"],len(body))==(0x069e,0x06c7,41,0x06c7),"exact contiguous final-window code bounds")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="e05dd251bd3d06c3922c980ef2657ceb3265ebfcc76fb141a808533b9c2c837a","original final-window source SHA")
 need(len(a["segments"])==len(EXPECTED),"segment count")
 for seg,(name,start,end,hx,br,rel,target,tok) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"segment identity "+name)
  need(body[start:end]==bytes.fromhex(hx),"exact original source IL bytes "+name)
  if br is not None:
   need((int(seg["branch_il"],16),seg["branch_rel_s32"],int(seg["branch_target_il"],16),seg["field_token"])==(br,rel,target,tok),"loop branch witness "+name)
   need(body[br]==0x3f and struct.unpack_from("<i",body,br+1)[0]==rel and br+5+rel==target,"original blt target "+name)
 need(b"".join(bytes.fromhex(seg[3]) for seg in EXPECTED)==body[lo:hi],"complete contiguous original final IL coverage")
 need(body[0x06c5:0x06c7]==bytes.fromhex("072a"),"original ldloc.1 and ret")
 need((a["return_local"],a["inner_index_local"],a["inner_parent_local"],a["outer_index_local"],a["outer_parent_local"])==(1,15,14,13,1),"source local references")
 need(a["next_contiguous_il"] is None and a["method_code_end_il"]=="0x06C7","method code ends at final return")
 full=a["complete_method_byte_coverage"]
 need((full["start_il"],full["end_exclusive_il"],full["full_il_sha256"])==("0x0000","0x06C7",m["code_sha256"]),"entire source method boundary")
 need(set(a["fields"])==set(FIELDS),"field token count")
 for token,(owner,name,row,sig) in FIELDS.items():
  f=a["fields"][token]
  need((f["token"],f["owner"],f["name"],f["metadata_row_hex"],f["signature_hex"])==(token,owner,name,row,sig),"field witness "+token)
  need(base.field(pe,s,b,z,o,sb,bb,field_owners,int(token,16))==(row,(owner,""),name,sig),"matching original FieldDef "+token)
 return {"fact_id":"FACT-0286","source":"DLL-001","source_sha256":a["source_sha256"],"complete_method_size":len(body),"method_sha256":m["code_sha256"],"fields":sorted(FIELDS),"code_end":"0x06C7","authored_data_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_PARSER_LOOP_EXITS_RETURN_V1" and w["source_ids"]==["DLL-001"],"witness provenance")
  print(json.dumps(verify(args.dll,w),sort_keys=True,indent=2))
  print("PROVE_SKILL_DATA_MAN_RSF_PARSER_LOOP_EXITS_RETURN: PASS")
  return 0
 except Exception as exc:
  print("PROVE_SKILL_DATA_MAN_RSF_PARSER_LOOP_EXITS_RETURN: FAIL",str(exc))
  return 1
if __name__=="__main__":raise SystemExit(main())
