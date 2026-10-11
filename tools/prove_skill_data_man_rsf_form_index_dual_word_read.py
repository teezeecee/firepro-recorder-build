#!/usr/bin/env python3
"""FACT-0279: source-only proof for RSF FormDispInfo.formIdx dual word read."""
import argparse,hashlib,json
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_index_dual_word_read.summary.json"
EXPECTED=[
 ("source_word_assign_formIdx",0x04cc,0x04df,"11100308911e62030817589160d17dd97c0004"),
 ("same_source_word_assign_local17",0x04df,0x04ed,"0308911e62030817589160d11311"),
 ("advance_cursor_two_after_both_reads",0x04ed,0x04f1,"0818580c"),
]
def need(condition,message):
 if not condition:raise RuntimeError(message)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original matching DLL identity")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef identity")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"original method IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,a["length_bytes"])==(0x4cc,0x4f1,37),"exact contiguous IL window")
 need(hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"]=="8588bd8b25ff5e6e65b25ec5c33cfecb3fbaf75bc36ffacc6583334b38a3573b","matching original IL bytes")
 need(len(a["segments"])==len(EXPECTED),"segment count")
 for seg,(name,start,end,hx) in zip(a["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,start,end,hx),"witness segment identity "+name)
  need(body[start:end]==bytes.fromhex(hx),"source opcode bytes "+name)
 need(b"".join(bytes.fromhex(s[3]) for s in EXPECTED)==body[lo:hi],"complete original source segment coverage")
 need((a["source_input_arg"],a["cursor_local"],a["form_entry_local"],a["word_local"])==("arg1",2,16,17),"original source local references")
 t=a["owner_typedef"]
 own=base.typedef(pe,rows,s,ix,z,o,sb,0x0a73)
 nextown=base.typedef(pe,rows,s,ix,z,o,sb,0x0a74)
 need(t["token"]=="0x02000A73" and t["name"]==own[1]=="FormDispInfo","original type identity")
 need(own[4]==int(t["first_field_rid"],16)==0x7cd8 and nextown[4]==int(t["next_type_first_field_rid"],16)==0x7ce8,"original type field ownership bounds")
 field=a["field"]
 need((field["token"],field["owner"],field["name"],field["metadata_row_hex"],field["signature_hex"])==("0x04007CD9","FormDispInfo","formIdx","06009670010001000000","0608"),"source field witness")
 need(base.field(pe,s,b,z,o,sb,bb,fm,0x04007CD9)==(field["metadata_row_hex"],("FormDispInfo",""),"formIdx",field["signature_hex"]),"original field metadata identity")
 return {"fact_id":"FACT-0279","source":"DLL-001","il_start":"0x04CC","il_end_exclusive":"0x04F1","window_sha256":a["source_sha256"],"field":"FormDispInfo.formIdx","local_word":17,"cursor_increment":2,"authored_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_INDEX_DUAL_WORD_READ_V1" and w["source_ids"]==["DLL-001"],"source witness identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_INDEX_DUAL_WORD_READ: PASS");return 0
 except Exception as exc:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_INDEX_DUAL_WORD_READ: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
