#!/usr/bin/env python3
"""FACT-0280: original RSF form lookup and two form-part field transfers."""
import argparse,hashlib,json
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_data_lookup_and_parts_transfer.summary.json"
EXPECTED=[
 ("optional_skill_block_form_index",1265,1282,"161312063908000000067bd60e00041312"),
 ("get_form_data_by_source_arguments",1282,1300,"7edc260004111111120e046f171f00061313"),
 ("copy_two_source_fields_to_form_display",1300,1328,"111011137bcb2600047dda7c0004111011137bcc2600047de77c0004")
]
FIELDS={
 "0x04000ED6":("SkillInfo","blockFormIdx","0600974c010001000000","0608"),
 "0x040026DC":("FormDataMan","inst","16000622010037190000","0612900c"),
 "0x040026CB":("FormData","partsNum","0600ee76010001000000","0608"),
 "0x040026CC":("FormData","formPartsList","0600f814020031190000","061d129000"),
 "0x04007CDA":("FormDispInfo","partsNum","0600ee76010001000000","0608"),
 "0x04007CE7":("FormDispInfo","formPartsList","0600f814020031190000","061d129000")
}
def need(ok,message):
 if not ok:raise RuntimeError(message)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL identity")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original parser MethodDef")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original parser header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"original parser full IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"])==(0x04f1,0x0530,63),"contiguous source window")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="6c0df9c5ae63c2d3e3ac6b1f0a94a6a97ff9eb0550b403be79df3451ae8dca90","original source region SHA")
 need(len(a["segments"])==len(EXPECTED),"three bounded original source spans")
 for seg,(name,start,end,hx) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"segment witness "+name)
  need(body[start:end]==bytes.fromhex(hx),"original IL segment "+name)
 need(b"".join(bytes.fromhex(x[3]) for x in EXPECTED)==body[lo:hi],"complete original source window coverage")
 need((a["source_form_index_local"],a["optional_skill_local"],a["block_form_index_local"],a["form_data_local"],a["form_display_local"],a["source_arg4"])==(17,0,18,19,16,"arg4"),"exact IL local and argument map")
 br=a["branch"]
 need((br["branch_opcode_il"],br["branch_target_il"],br["relative_s32"])==("0x04F5","0x0502",8),"branch witness")
 need(body[0x04f5]==0x39 and int.from_bytes(body[0x04f6:0x04fa],"little",signed=True)==8 and 0x04fa+8==0x0502,"original branch target")
 need(set(a["fields"])==set(FIELDS),"source FieldDef count and token set")
 for token,(owner,name,row,sig) in FIELDS.items():
  fld=a["fields"][token]
  need((fld["owner"],fld["name"],fld["row_hex"],fld["signature_hex"])==(owner,name,row,sig),"field witness "+token)
  need(base.field(pe,s,b,z,o,sb,bb,fm,int(token,16))==(row,(owner,""),name,sig),"original FieldDef "+token)
 meth=a["methoddef"];md2=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06001F17)
 need((meth["token"],meth["owner"],meth["name"],meth["row_hex"],meth["signature_hex"],meth["rva"])==("0x06001F17","FormDataMan","GetFormData","d0a41000000086000e0209005d0b02005516","2003129008080808","0x0010A4D0"),"method witness")
 need((md2[0],md2[1],md2[4],md2[5],md2[7])==(meth["row_hex"],int(meth["rva"],16),meth["name"],meth["signature_hex"],(meth["owner"],"")),"original GetFormData MethodDef")
 return {"source":"DLL-001","fact_id":"FACT-0280","window_sha256":a["source_sha256"],"fielddef_count":6,"methoddef_count":1,"branch_target":"0x0502","runtime_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_DATA_LOOKUP_AND_PARTS_TRANSFER_V1" and w["source_ids"]==["DLL-001"],"witness identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_DATA_LOOKUP_AND_PARTS_TRANSFER: PASS");return 0
 except Exception as exc:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_DATA_LOOKUP_AND_PARTS_TRANSFER: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
