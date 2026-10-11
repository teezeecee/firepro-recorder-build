#!/usr/bin/env python3
"""FACT-0283 exact original DLL source proof for three conditional flags OR updates."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_flag_bit_or_updates.summary.json"
EXPECTED=[
 ("read_flag_bit_source_byte_to_local4",0x05a1,0x05aa,"03082517580c911304"),
 ("if_bit_1_set_or_flags_0x400",0x05aa,0x05c6,"1104175f39130000001110257be67c00042000040000607de67c0004"),
 ("if_bit_2_set_or_flags_0x800",0x05c6,0x05e2,"1104185f39130000001110257be67c00042000080000607de67c0004"),
 ("if_bit_4_set_or_flags_0x100",0x05e2,0x05fe,"11041a5f39130000001110257be67c00042000010000607de67c0004"),
]
CHECKS=[(1,0x400,0x05ae,0x05c6),(2,0x800,0x05ca,0x05e2),(4,0x100,0x05e6,0x05fe)]
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL SHA/size")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef identity")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"full original parser method SHA")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"])==(0x5a1,0x5fe,93),"exact source window")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="c9c9f67cafdde8edf5443e35c6a54823ee42a7578715dfe019392ff90e8fd2b6","source window SHA")
 need(len(a["segments"])==len(EXPECTED),"segment coverage count")
 for seg,(name,start,end,hx) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"witness segment "+name)
  need(body[start:end]==bytes.fromhex(hx),"source bytes "+name)
 need(b"".join(bytes.fromhex(e[3]) for e in EXPECTED)==body[lo:hi],"contiguous coverage complete")
 need((a["source_input_arg"],a["cursor_local"],a["form_entry_local"],a["source_byte_local"])==("arg1",2,16,4),"exact original local map")
 need(a["branch_opcode"]=="brfalse" and a["branch_relative_s32"]==19 and a["next_unparsed_il"]=="0x05FE","branch witness")
 for seg,(mask,flag_value,at,target) in zip(a["segments"][1:],CHECKS):
  need((seg["bit_mask"],int(seg["flags_or_mask"],16),int(seg["branch_opcode_il"],16),int(seg["branch_target_il"],16))==(mask,flag_value,at,target),"source check witness")
  need(body[at]==0x39 and struct.unpack_from("<i",body,at+1)[0]==19 and (at+5+19)==target,"actual brfalse target")
  start=int(seg["start_il"],16)
  need(body[start+3]==0x5f,"actual original and bitwise operation")
  need(body[target-6]==0x60 and body[target-5]==0x7d and body[target-4:target]==bytes.fromhex("e67c0004"),"actual OR and stfld flags")
 field=a["field"]
 need((field["token"],field["owner"],field["name"],field["metadata_row_hex"],field["signature_hex"])==("0x04007CE6","FormDispInfo","flags","0600314c010093370000","0611a9d0"),"original flags field witness")
 need(base.field(pe,s,b,z,o,sb,bb,fm,0x04007CE6)==(field["metadata_row_hex"],("FormDispInfo",""),"flags",field["signature_hex"]),"original FieldDef metadata identity")
 return {"fact_id":"FACT-0283","source":"DLL-001","window_sha256":a["source_sha256"],"conditional_masks":[x[0] for x in CHECKS],"flags_or_masks":[hex(x[1]) for x in CHECKS],"next_il":"0x05FE","authored_flags_meaning":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_FLAG_BIT_OR_UPDATES_V1" and w["source_ids"]==["DLL-001"],"witness identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_FLAG_BIT_OR_UPDATES: PASS")
  return 0
 except Exception as exc:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_FLAG_BIT_OR_UPDATES: FAIL",str(exc))
  return 1
if __name__=="__main__":raise SystemExit(main())
