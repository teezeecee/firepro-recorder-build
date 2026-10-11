#!/usr/bin/env python3
"""FACT-0281 exact retail DLL source proof: formOfsPos Vector2 and dispFrm byte."""
import argparse, hashlib, json
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_offset_pos_and_disp_frame.summary.json"
EXPECTED=[
 ("read_first_signed_form_offset_component",0x0530,0x053a,"03082517580c91671305"),
 ("read_second_signed_form_offset_component",0x053a,0x0544,"03082517580c91671306"),
 ("construct_scaled_vector2_assign_form_offset_position",0x0544,0x0562,"111011056b22000000405a11066b22000000405a738800000a7ddb7c0004"),
 ("read_unsigned_byte_assign_disp_frame",0x0562,0x0570,"111003082517580c917ddc7c0004"),
]
FIELDS={
 "0x04007CDB":("FormDispInfo","formOfsPos","0600f7760100cb000000","061131"),
 "0x04007CDC":("FormDispInfo","dispFrm","06000277010001000000","0608"),
}
def need(ok,msg):
 if not ok: raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL")
 ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original method metadata")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"original full parser IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"])==(0x530,0x570,64),"exact IL window bounds")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="c104bc32de801488e4bec4a92f56d4f948f6a1c258d82114f4bd04a98cc79158","exact source region SHA")
 need(len(a["segments"])==len(EXPECTED),"source segment count")
 for seg,(name,start,end,hx) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"witness segment "+name)
  need(body[start:end]==bytes.fromhex(hx),"source opcode segment "+name)
 need(b"".join(bytes.fromhex(x[3]) for x in EXPECTED)==body[lo:hi],"contiguous coverage")
 need((a["source_input_arg"],a["cursor_local"],a["form_entry_local"],a["signed_component_locals"],a["float_multiplier_ieee754_le_hex"])==("arg1",2,16,[5,6],"00000040"),"input cursors and float multiplier witness")
 need(set(a["fields"])==set(FIELDS),"source fields")
 for token,(owner,name,raw,sig) in FIELDS.items():
  x=a["fields"][token]
  need((x["owner"],x["name"],x["metadata_row_hex"],x["signature_hex"])==(owner,name,raw,sig),"field witness "+token)
  need(base.field(pe,s,b,z,o,sb,bb,fm,int(token,16))==(raw,(owner,""),name,sig),"original FieldDef "+token)
 tr=a["vector2_typeref"];idx=0x0c
 raw=pe[o[1]+(idx-1)*z[1]:o[1]+idx*z[1]]
 wide=z[1]-2*s
 ni=int.from_bytes(raw[wide:wide+s],"little");ns=int.from_bytes(raw[wide+s:wide+2*s],"little")
 need((tr["token"],tr["owner"],tr["name"],tr["metadata_row_hex"])==("0x0100000C","UnityEngine","Vector2","0600b5ac000080a60000"),"Vector2 typeref witness")
 need(raw.hex()==tr["metadata_row_hex"] and (base.s_at(pe,sb,ni),base.s_at(pe,sb,ns))==("Vector2","UnityEngine"),"original TypeRef")
 mr=a["constructor_memberref"];rid=0x88
 raw=pe[o[10]+(rid-1)*z[10]:o[10]+rid*z[10]];cw=z[10]-s-b
 coded=int.from_bytes(raw[:cw],"little");ni=int.from_bytes(raw[cw:cw+s],"little");si=int.from_bytes(raw[cw+s:cw+s+b],"little")
 need((mr["token"],mr["metadata_row_hex"],mr["coded_parent_hex"],mr["parent_typeref_token"],mr["name"],mr["signature_hex"])==("0x0A000088","61000000eb4f06003a4b0000","0x61","0x0100000C",".ctor","2002010c0c"),"ctor witness")
 need(raw.hex()==mr["metadata_row_hex"] and coded==0x61 and base.s_at(pe,sb,ni)==".ctor" and base.blob(pe,bb,si).hex()=="2002010c0c","original constructor MemberRef")
 return {"source":"DLL-001","fact_id":"FACT-0281","window_sha256":a["source_sha256"],"float_multiplier":2.0,"original_fields":["FormDispInfo.formOfsPos","FormDispInfo.dispFrm"],"authored_animation_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_OFFSET_POS_AND_DISP_FRAME_V1" and w["source_ids"]==["DLL-001"],"witness identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_OFFSET_POS_AND_DISP_FRAME: PASS")
  return 0
 except Exception as ex:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_OFFSET_POS_AND_DISP_FRAME: FAIL",str(ex));return 1
if __name__=="__main__": raise SystemExit(main())
