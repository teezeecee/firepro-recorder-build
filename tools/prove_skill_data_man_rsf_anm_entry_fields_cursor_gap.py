#!/usr/bin/env python3
"""FACT-0276: exact retail RSF WrestlerAnmData fields and skipped cursor positions."""
import argparse,hashlib,json
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json"
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"matching original DLL SHA and size")
 ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original MethodDef raw row")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"] and len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"full original MethodDef IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,hi-lo)==(0x3cc,0x470,164) and hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"],"exact contiguous 164 original bytes")
 names=["atkColAng_from_local3","atkColPos_from_local7","atkColSize_from_local10","seven_unsigned_source_bytes","three_cursor_increments_without_reads","two_more_unsigned_source_bytes"]
 sizes=[8,9,9,98,12,28]
 seg=a["segments"];need([x["name"] for x in seg]==names and len(seg)==6,"exact source segment names")
 at=lo
 for x,sz in zip(seg,sizes):
  begin=int(x["start_il"],16);end=int(x["end_exclusive_il"],16);raw=bytes.fromhex(x["il_hex"])
  need(begin==at and end==begin+sz and len(raw)==sz and body[begin:end]==raw,"exact source span "+x["name"])
  at=end
 need(at==hi,"contiguous source coverage")
 expected=[
 (0x04007C9A,"atkColAng","06005873010014000000","060c","local3"),
 (0x04007C98,"atkColPos","06000a730100cb000000","061131","local7"),
 (0x04007C99,"atkColSize","060014730100cb000000","061131","local10"),
 (0x04007C93,"formNum","06000c75010001000000","0608",64),
 (0x04007C94,"loopReturnPoint","06001475010001000000","0608",65),
 (0x04007C95,"loopReturnTo","06002475010001000000","0608",66),
 (0x04007C96,"fallTiming","06003175010001000000","0608",67),
 (0x04007C97,"terrainColType","06003c750100fd370000","0611a9bc",68),
 (0x04007C9B,"hitSE","06004b75010001000000","0608",69),
 (0x04007C9C,"cheerLevel","0600404c010001000000","0608",70),
 (0x04007C9D,"anmStartState","060061750100f53a0000","0611a9c0",74),
 (0x04007C9E,"anmEndState","06006f75010098370000","0611a9c4",75)]
 need(len(a["fields"])==len(expected),"twelve original source FieldDefs")
 for f,(token,name,raw,sig,source) in zip(a["fields"],expected):
  need((f["token"],f["owner"],f["name"],f["metadata_row_hex"],f["signature_hex"],f["source"])==(f"0x{token:08X}","WrestlerAnmData",name,raw,sig,source),"claimed original field "+name)
  need(base.field(pe,s,b,z,o,sb,bb,fm,token)==(raw,("WrestlerAnmData",""),name,sig),"actual original FieldDef "+name)
 need((a["source_record_object_local"],a["source_cursor_local"],a["source_array_argument"],a["postincrement_old_cursor"])==(14,2,"arg1",True),"source local cursor")
 need(a["source_byte_offsets_read"]==[64,65,66,67,68,69,70,74,75] and a["cursor_positions_skipped_without_read"]==[71,72,73],"correct old-cursor offsets")
 need(seg[3]["relative_offsets"]==list(range(64,71)) and seg[4]["relative_offsets"]==[71,72,73] and seg[5]["relative_offsets"]==[74,75],"segmented input provenance")
 readseq=bytes.fromhex("110e03082517580c91");incseq=bytes.fromhex("0817580c")
 sourcebytes=body[0x3e6:0x448];lastbytes=body[0x454:0x470]
 for j,tok in enumerate((0x04007C93,0x04007C94,0x04007C95,0x04007C96,0x04007C97,0x04007C9B,0x04007C9C)):
  need(sourcebytes[14*j:14*(j+1)]==readseq+b"\x7d"+tok.to_bytes(4,"little"),"seven consecutive original unsigned source-byte writes")
 for j,tok in enumerate((0x04007C9D,0x04007C9E)):
  need(lastbytes[14*j:14*(j+1)]==readseq+b"\x7d"+tok.to_bytes(4,"little"),"two trailing original unsigned source-byte writes")
 need(body[0x448:0x454]==incseq*3 and body[0x3cc:0x3d4]==bytes.fromhex("110e097d9a7c0004") and body[0x3d4:0x3dd]==bytes.fromhex("110e11077d987c0004") and body[0x3dd:0x3e6]==bytes.fromhex("110e110a7d997c0004"),"three original local sources and exact no-read increments")
 return {"source":"DLL-001","method_sha256":m["code_sha256"],"window_sha256":a["source_sha256"],"original_field_count":12,"source_input_offsets_read":a["source_byte_offsets_read"],"cursor_positions_skipped":a["cursor_positions_skipped_without_read"],"gameplay_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_ANM_ENTRY_FIELDS_AND_CURSOR_GAP_V1" and w["source_ids"]==["DLL-001"],"witness source manifest")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_ANM_ENTRY_FIELDS_CURSOR_GAP: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_ANM_ENTRY_FIELDS_CURSOR_GAP: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
