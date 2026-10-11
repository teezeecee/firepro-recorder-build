#!/usr/bin/env python3
"""FACT-0285 exact original retail DLL source-only proof; no game assets or runtime."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_sound_effect_fields.summary.json"
EXPECTED=[
 ("read_form_byte_for_flags",0x0641,0x064a,"03082517580c911304"),
 ("conditional_flags_or_0x200_from_mask32",0x064a,0x0667,"11041f205f39130000001110257be67c00042000020000607de67c0004"),
 ("assign_ring_vibration_two_bits",0x0667,0x0674,"111011041963195f7de57c0004"),
 ("read_second_form_byte",0x0674,0x067d,"03082517580c911304"),
 ("assign_se_id_low_six",0x067d,0x0689,"111011041f3f5f7de27c0004"),
 ("assign_se_level_high_two",0x0689,0x0696,"111011041c63195f7de37c0004"),
 ("initialize_effect_id_minus_one",0x0696,0x069e,"1110157de47c0004")
]
FIELDS={
 "0x04007CE2":("FormDispInfo","seID","060031770100073a0000","0611aa0c"),
 "0x04007CE3":("FormDispInfo","seLevel","06009e4e050001000000","0608"),
 "0x04007CE4":("FormDispInfo","effectID","0600a64e050001000000","0608"),
 "0x04007CE5":("FormDispInfo","ringVibration","06003677010001000000","0608"),
 "0x04007CE6":("FormDispInfo","flags","0600314c010093370000","0611a9d0")
}
def need(condition,message):
 if not condition: raise RuntimeError(message)
def verify(path,w):
 pe=Path(path).read_bytes(); d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL SHA and size")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 field_owners,method_owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,method_owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"entire original IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"])==(0x0641,0x069e,93),"contiguous IL bounds")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="9676632c4efd1721c279ace3496f80d84e077f0cf4b1e06a430ff3def3248765","original IL SHA")
 need(len(a["segments"])==len(EXPECTED),"original segment count")
 for seg,(name,start,end,hx) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"segment metadata "+name)
  need(body[start:end]==bytes.fromhex(hx),"original source bytes "+name)
 need(b"".join(bytes.fromhex(x[3]) for x in EXPECTED)==body[lo:hi],"exact continuous original source coverage")
 need((a["source_byte_local"],a["cursor_local"],a["form_entry_local"],a["cursor_advances"])==(4,2,16,2),"locals and cursor counts")
 need(body[0x0641:0x064a]==body[0x0674:0x067d]==bytes.fromhex("03082517580c911304"),"two original independent unsigned cursor reads")
 need(body[0x064f]==0x39 and struct.unpack_from("<i",body,0x0650)[0]==19 and 0x0654+19==0x0667,"original brfalse 0x064f to 0x0667")
 need((a["flags_branch_il"],a["flags_branch_target_il"],a["flags_branch_rel_s32"])==("0x064F","0x0667",19),"branch witness")
 need(set(a["fields"])==set(FIELDS),"original field token coverage")
 for token,(owner,name,row,sig) in FIELDS.items():
  f=a["fields"][token]
  need((f["token"],f["owner"],f["name"],f["metadata_row_hex"],f["signature_hex"])==(token,owner,name,row,sig),"FieldDef witness "+token)
  need(base.field(pe,s,b,z,o,sb,bb,field_owners,int(token,16))==(row,(owner,""),name,sig),"original raw FieldDef "+token)
 need(a["next_contiguous_il"]=="0x069E","next original IL boundary")
 return {"fact_id":"FACT-0285","source":"DLL-001","window_sha256":a["source_sha256"],"next_source_il":a["next_contiguous_il"],"original_fielddefs":sorted(FIELDS),"authoring_and_runtime_semantics":"OPEN"}
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--dll",required=True);args=parser.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_SOUND_EFFECT_FIELDS_V1" and w["source_ids"]==["DLL-001"],"witness provenance")
  print(json.dumps(verify(args.dll,w),sort_keys=True,indent=2))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_SOUND_EFFECT_FIELDS: PASS")
  return 0
 except Exception as exc:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_SOUND_EFFECT_FIELDS: FAIL",str(exc))
  return 1
if __name__=="__main__":raise SystemExit(main())
