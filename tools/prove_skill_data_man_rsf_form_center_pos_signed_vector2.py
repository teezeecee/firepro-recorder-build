#!/usr/bin/env python3
"""FACT-0278: prove original FormDispInfo.centerPos signed-byte Vector2 source IL."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_center_pos_signed_vector2.summary.json"
def need(ok,message):
 if not ok:raise RuntimeError(message)
def verify(dll,w):
 pe=Path(dll).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL")
 ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original ParseRSFData method identity")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"] and len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"original complete IL and header")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,hi-lo)==(0x4a6,0x4cc,38) and hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"],"38 original IL bytes")
 expected=[
 ("read_x_unsigned_then_signed_to_local5",0x4a6,0x4b0,"03082517580c91671305"),
 ("read_y_unsigned_then_signed_to_local6",0x4b0,0x4ba,"03082517580c91671306"),
 ("construct_Vector2_and_store_centerPos",0x4ba,0x4cc,"111011056b11066b738800000a7dd87c0004")]
 need(len(a["segments"])==3,"three bounded original spans")
 at=lo
 for seg,(name,start,end,hx) in zip(a["segments"],expected):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx) and at==start and body[start:end]==bytes.fromhex(hx),"original source span "+name)
  at=end
 need(at==hi and b"".join(bytes.fromhex(x[3]) for x in expected)==body[lo:hi],"complete contiguous original source window")
 need((a["source_input_arg"],a["cursor_local"],a["form_entry_local"],a["signed_x_local"],a["signed_y_local"])==("arg1",2,16,5,6),"source locals and input arg")
 # Verify raw original FieldDef and full owner mapping.
 fd=a["field"];token=int(fd["token"],16)
 need((fd["token"],fd["owner"],fd["name"],fd["signature_hex"])==("0x04007CD8","FormDispInfo","centerPos","061131"),"destination witness")
 need(base.field(pe,s,b,z,o,sb,bb,fm,token)==(fd["metadata_row_hex"],("FormDispInfo",""),"centerPos",fd["signature_hex"]),"original destination FieldDef")
 # MemberRefParent coded index 0x61 -> TypeRef row 12.
 tr=a["vector2_typeref"];tidx=int(tr["token"],16)&0xffffff
 need(tr["token"]=="0x0100000C" and tr["name"]=="Vector2" and tr["owner"]=="UnityEngine","original type witness")
 raw=pe[o[1]+(tidx-1)*z[1]:o[1]+tidx*z[1]]
 coded_parent_width=z[1]-2*s
 nameidx=int.from_bytes(raw[coded_parent_width:coded_parent_width+s],"little")
 nsidx=int.from_bytes(raw[coded_parent_width+s:coded_parent_width+2*s],"little")
 need(raw.hex()==tr["metadata_row_hex"] and (base.s_at(pe,sb,nameidx),base.s_at(pe,sb,nsidx))==("Vector2","UnityEngine"),"original Vector2 TypeRef metadata")
 mr=a["constructor_memberref"];rid=int(mr["token"],16)&0xffffff
 need(mr["token"]=="0x0A000088","original newobj MemberRef token")
 raw=pe[o[10]+(rid-1)*z[10]:o[10]+rid*z[10]]
 coded_len=z[10]-s-b;cl=int.from_bytes(raw[:coded_len],"little")
 nameidx=int.from_bytes(raw[coded_len:coded_len+s],"little")
 sigidx=int.from_bytes(raw[coded_len+s:coded_len+s+b],"little")
 need(raw.hex()==mr["metadata_row_hex"] and cl==0x61 and cl&7==1 and cl>>3==tidx,"original MemberRef parent TypeRef")
 need(base.s_at(pe,sb,nameidx)==mr["name"]==".ctor" and base.blob(pe,bb,sigidx).hex()==mr["signature_hex"]=="2002010c0c","original constructor name and two float32 arguments")
 need(mr["parent_typeref_token"]==tr["token"] and mr["coded_parent_hex"]=="0x61","metadata parent linkage")
 return {"source":"DLL-001","window_sha256":a["source_sha256"],"field":"FormDispInfo.centerPos","signed_source_bytes":2,"memberref":"UnityEngine.Vector2..ctor(float32,float32)","runtime_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_CENTER_POS_SIGNED_VECTOR2_V1" and w["source_ids"]==["DLL-001"],"source witness identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_CENTER_POS_SIGNED_VECTOR2: PASS");return 0
 except Exception as ex:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_CENTER_POS_SIGNED_VECTOR2: FAIL",str(ex));return 1
if __name__=="__main__":raise SystemExit(main())
