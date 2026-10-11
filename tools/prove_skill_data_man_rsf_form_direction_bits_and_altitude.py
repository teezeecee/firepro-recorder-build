#!/usr/bin/env python3
"""FACT-0284: exact source proof for original RSF form direction bits and altitude."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_direction_bits_and_altitude.summary.json"
EXPECTED=[
 ("initialize_dir_LR_zero",0x05fe,0x0606,"1110167ddf7c0004"),
 ("conditionally_assign_dir_LR_one_if_bit8",0x0606,0x0617,"11041e5f39080000001110177ddf7c0004"),
 ("initialize_dir_UD_zero",0x0617,0x061f,"1110167de07c0004"),
 ("conditionally_assign_dir_UD_one_if_bit128",0x061f,0x0634,"110420800000005f39080000001110177de07c0004"),
 ("assign_altitude_three_bits",0x0634,0x0641,"111011041a631d5f7de17c0004")
]
FIELDS={
 "0x04007CDF":("FormDispInfo","dir_LR","06001a77010001000000","0608"),
 "0x04007CE0":("FormDispInfo","dir_UD","06002177010001000000","0608"),
 "0x04007CE1":("FormDispInfo","altitude","06002877010001000000","0608")
}
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original retail DLL SHA and size")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef identity")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"original full parser IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"])==(0x05fe,0x0641,67),"exact contiguous original IL bounds")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="9fa1cfe167f8cf98d33726a5e246fc22c9501001df4bed430a1205d512501916","original source window digest")
 need(len(a["segments"])==len(EXPECTED),"segment count")
 for seg,(name,start,end,hx) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"segment witness "+name)
  need(body[start:end]==bytes.fromhex(hx),"original IL bytes "+name)
 need(b"".join(bytes.fromhex(x[3]) for x in EXPECTED)==body[lo:hi],"full original contiguous segment coverage")
 need(a["source_byte_local"]==4 and a["form_entry_local"]==16 and a["cursor_modified_in_window"] is False,"witness local references")
 need(a["input_from_previous_region"]=="local4 populated at FACT-0283 IL+0x05A1..+0x05A9","prior original local4 source")
 for seg,mask,branch,target in ((a["segments"][1],8,0x060a,0x0617),(a["segments"][3],128,0x0627,0x0634)):
  need((seg["bit_mask"],int(seg["branch_il"],16),int(seg["branch_target_il"],16),seg["branch_rel_s32"])==(mask,branch,target,8),"branch witness "+hex(mask))
  need(body[branch]==0x39 and struct.unpack_from("<i",body,branch+1)[0]==8 and branch+5+8==target,"original brfalse opcode/target "+hex(mask))
 need((a["segments"][4]["right_shift"],a["segments"][4]["and_mask"])==(4,7),"altitude mask and shift witness")
 need(set(a["fields"])==set(FIELDS),"FieldDef token coverage")
 for token,(owner,name,row,sig) in FIELDS.items():
  field=a["fields"][token]
  need((field["token"],field["owner"],field["name"],field["metadata_row_hex"],field["signature_hex"])==(token,owner,name,row,sig),"witness FieldDef "+token)
  need(base.field(pe,s,b,z,o,sb,bb,fm,int(token,16))==(row,(owner,""),name,sig),"original DLL FieldDef "+token)
 return {"fact_id":"FACT-0284","source":"DLL-001","window_sha256":a["source_sha256"],"next_source_il":a["next_contiguous_il"],"original_fielddefs":sorted(FIELDS),"authored_direction_altitude_meaning":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_DIRECTION_BITS_AND_ALTITUDE_V1" and w["source_ids"]==["DLL-001"],"source-only witness identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_DIRECTION_BITS_AND_ALTITUDE: PASS")
  return 0
 except Exception as exc:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_DIRECTION_BITS_AND_ALTITUDE: FAIL",str(exc))
  return 1
if __name__=="__main__":raise SystemExit(main())
