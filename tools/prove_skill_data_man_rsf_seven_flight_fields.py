#!/usr/bin/env python3
"""FACT-0272 prove seven consecutive original SkillData field writes."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_seven_flight_fields.summary.json"
def need(ok,why):
 if not ok:raise RuntimeError(why)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original DLL SHA and size")
 sections,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,sections,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
 sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,sections,s,b,ix,z,o,sb,bb,owners,0x0600525F)
 body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef row")
 need(pe[base.off(sections,md[1]):md[8]].hex()==m["header_hex"] and len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"complete original IL")
 start=int(a["start_il"],16);end=int(a["end_exclusive_il"],16)
 need((start,end,end-start)==(0x2de,0x33b,93) and hashlib.sha256(body[start:end]).hexdigest()==a["source_sha256"],"exact 93-byte source block")
 fields=a["source_fields"];need(len(fields)==7,"seven source writes")
 pfx=bytes.fromhex("0703082517580c91")
 at=start
 for i,f in enumerate(fields):
  has_float=i in (4,5)
  seq=pfx+(bytes([0x6b]) if has_float else b"")+bytes([0x7d])+struct.pack("<I",int(f["token"],16))
  need(at==int(f["il_offset"],16) and seq.hex()==f["il_hex"] and body[at:at+len(seq)]==seq,"actual original source IL "+f["name"])
  need(f["relative_input_byte"]==40+i,"corrected original cursor position "+f["name"])
  need(f["conversion"]==("ldelem.u1; conv.r4" if has_float else "ldelem.u1"),"original byte conversion type")
  row=base.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))
  need((row[0],row[1],row[2])==(f["metadata_row_hex"],("SkillData",""),f["name"]),"raw original FieldDef "+f["name"])
  at+=len(seq)
 need(at==end and a["no_branches_within_window"],"entire block continuous, no extra instructions")
 return {"source":"DLL-001","whole_method_sha256":m["code_sha256"],"window_sha256":a["source_sha256"],"fields":len(fields),"source_offsets":[x["relative_input_byte"] for x in fields],"explicit_float_conversions":[x["name"] for x in fields if x["conversion"].endswith("conv.r4")],"gameplay_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_SEVEN_FLIGHT_FIELD_WRITES_V1" and w["source_ids"]==["DLL-001"],"witness source")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True));print("PROVE_SKILL_DATA_MAN_RSF_SEVEN_FLIGHT_FIELDS: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_SEVEN_FLIGHT_FIELDS: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
