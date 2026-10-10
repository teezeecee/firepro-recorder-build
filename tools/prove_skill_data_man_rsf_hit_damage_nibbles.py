#!/usr/bin/env python3
"""FACT-0273: prove original packed hit-damage field writes, source-only."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_hit_damage_nibbles.summary.json"
def need(ok,msg):
 if not ok: raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes(); d=w["dll"]; m=d["method"]; a=d["window"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original DLL identity")
 ss,q=base.secs(pe); st,hs,rows,p=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
 sb=st["#Strings"][0]; bb=st["#Blob"][0]; fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F); body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original method row")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"] and len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"full original method")
 start=int(a["start_il"],16); end=int(a["end_exclusive_il"],16)
 need((start,end,end-start)==(0x33b,0x361,38) and hashlib.sha256(body[start:end]).hexdigest()==a["source_sha256"],"38 original IL bytes")
 seg=a["source_segments"]; need(len(seg)==4 and a["relative_input_byte"]==47 and a["postincrement_old_cursor"] and a["no_branches_within_window"],"source scope and cursor")
 expected=[
 ("read_byte_to_local4",0x33b,0x344,"03082517580c911304"),
 ("hitDmgType_Single",0x344,0x34f,"0711041f0f5f7d587c0004"),
 ("hitDmgType_Combo",0x34f,0x359,"0711041a637d597c0004"),
 ("ropeEscapeDir",0x359,0x361,"071f0f7d767c0004")]
 at=start
 for item,(name,lo,hi,hx) in zip(seg,expected):
  need((item["name"],int(item["il_start"],16),int(item["il_end_exclusive"],16),item["il_hex"])==(name,lo,hi,hx) and lo==at and body[lo:hi]==bytes.fromhex(hx),"original segment "+name)
  at=hi
 need(at==end and b"".join(bytes.fromhex(x[4]) for x in expected)==body[start:end],"complete branch-free original byte window")
 need(seg[0]["source_byte_offset"]==47,"correct previous source cursor +47")
 for item,token,name,raw,sig in zip(seg[1:],(0x04007C58,0x04007C59,0x04007C76),("hitDmgType_Single","hitDmgType_Combo","ropeEscapeDir"),("0600d14d050001000000","0600e34d050001000000","0600234c0100070c0000"),("0608","0608","0611a9b0")):
  row=base.field(pe,s,b,z,o,sb,bb,fm,token)
  need((item["token"],item["metadata_row_hex"],item["signature_hex"])==(f"0x{token:08X}",raw,sig),"claimed raw FieldDef "+name)
  need(row==(raw,("SkillData",""),name,sig),"original raw FieldDef "+name)
 need(seg[1]["operation"]=="field = local4 & 15" and seg[2]["operation"]=="field = local4 shr.un 4" and seg[3]["operation"]=="field = ldc.i4.s 15 (constant, not another parser byte)","bounded operation descriptions")
 return {"source":"DLL-001","window_sha256":a["source_sha256"],"source_input_byte":47,"field_count":3,"constant_rope_value":15,"gameplay_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_HIT_DAMAGE_NIBBLES_AND_ROPE_CONSTANT_V1" and w["source_ids"]==["DLL-001"],"source identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_HIT_DAMAGE_NIBBLES: PASS")
  return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_HIT_DAMAGE_NIBBLES: FAIL",str(e))
  return 1
if __name__=="__main__": raise SystemExit(main())
