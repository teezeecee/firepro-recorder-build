#!/usr/bin/env python3
"""FACT-0282 source-only original DLL proof of packed priority bits and initial flags."""
import argparse,hashlib,json
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_priorities_and_initial_flags.summary.json"
EXPECTED=[
 ("read_unsigned_source_priority_byte_to_local4",0x0570,0x0579,"03082517580c911304"),
 ("extract_form_priority_high_two_bits",0x0579,0x0586,"111011041c63195f7ddd7c0004"),
 ("extract_ring_priority_middle_three_bits",0x0586,0x0593,"1110110419631d5f7dde7c0004"),
 ("read_unsigned_source_byte_into_initial_flags",0x0593,0x05a1,"111003082517580c917de67c0004"),
]
FIELDS={
 "0x04007CDD":("FormDispInfo","formPri","06000a77010001000000","0608"),
 "0x04007CDE":("FormDispInfo","ringPri","06001277010098190000","0611a9c8"),
 "0x04007CE6":("FormDispInfo","flags","0600314c010093370000","0611a9d0"),
}
def need(ok,msg):
 if not ok: raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL identity")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"source MethodDef identity")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original parser header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"whole source IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"])==(0x570,0x5a1,49),"exact original source window")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="78bf425b69801c4c958d960905d88d7fd243294def1891207fc7883b6ac2ab66","original window byte digest")
 need(len(a["segments"])==len(EXPECTED),"segment count")
 for seg,(name,start,end,hx) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"segment witness "+name)
  need(body[start:end]==bytes.fromhex(hx),"original segment bytes "+name)
 need(b"".join(bytes.fromhex(x[3]) for x in EXPECTED)==body[lo:hi],"contiguous original IL coverage")
 need((a["source_input_arg"],a["cursor_local"],a["form_entry_local"],a["priority_byte_local"])==("arg1",2,16,4),"original input and locals")
 need((a["form_priority"]["right_shift"],a["form_priority"]["and_mask"],a["form_priority"]["source_byte_local"],a["form_priority"]["field_token"])==(6,3,4,"0x04007CDD"),"form priority source masks")
 need((a["ring_priority"]["right_shift"],a["ring_priority"]["and_mask"],a["ring_priority"]["source_byte_local"],a["ring_priority"]["field_token"])==(3,7,4,"0x04007CDE"),"ring priority source masks")
 need((a["flags"]["source_read"],a["flags"]["field_token"])==("ldelem.u1","0x04007CE6"),"flags initial source read")
 need(set(a["fields"])==set(FIELDS),"source fields count/tokens")
 for token,(owner,name,row,sig) in FIELDS.items():
  x=a["fields"][token]
  need((x["owner"],x["name"],x["metadata_row_hex"],x["signature_hex"])==(owner,name,row,sig),"witness field "+token)
  need(base.field(pe,s,b,z,o,sb,bb,fm,int(token,16))==(row,(owner,""),name,sig),"original FieldDef "+token)
 return {"fact_id":"FACT-0282","source":"DLL-001","window_sha256":a["source_sha256"],"source_window_end_exclusive":"0x05A1","fielddef_count":3,"form_pri_expression":"(u8 >> 6) & 3","ring_pri_expression":"(u8 >> 3) & 7","flags_value":"initial_unsigned_byte_only","authored_semantics":"OPEN"}
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--dll",required=True);args=parser.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_PRIORITIES_AND_INITIAL_FLAGS_V1" and w["source_ids"]==["DLL-001"],"source witness dataset identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_PRIORITIES_AND_INITIAL_FLAGS: PASS")
  return 0
 except Exception as err:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_PRIORITIES_AND_INITIAL_FLAGS: FAIL",str(err))
  return 1
if __name__=="__main__":raise SystemExit(main())
