#!/usr/bin/env python3
"""Source-only FACT-0277 original IL and metadata verifier."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_disp_info_array_entry.summary.json"
def check(path,w):
 pe=Path(path).read_bytes()
 assert (len(pe),hashlib.sha256(pe).hexdigest())==(w["dll_size"],w["dll_sha256"])
 ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(w["method_token"],16));body=md[9]
 assert (md[0],md[1],md[4],md[7])==(w["method_row_hex"],int(w["method_rva"],16),w["method_name"],(w["method_owner"],""))
 assert pe[base.off(ss,md[1]):md[8]].hex()==w["method_header_hex"]
 assert len(body)==w["method_bytes"] and hashlib.sha256(body).hexdigest()==w["method_sha256"]
 a=w["il_window"];start=int(a["start"],16);end=int(a["end_exclusive"],16)
 assert (start,end,end-start)==(0x470,0x4a6,54) and hashlib.sha256(body[start:end]).hexdigest()==a["sha256"]
 assert len(w["segments"])==4
 cursor=start
 for x in w["segments"]:
  lo=int(x["start"],16);hi=int(x["end_exclusive"],16)
  assert lo==cursor and body[lo:hi]==bytes.fromhex(x["hex"]);cursor=hi
 assert cursor==end
 v=w["metadata"]
 ty=v["type"];assert base.typedef(pe,rows,s,ix,z,o,sb,int(ty["token"],16)&0xffffff)[:3]==(ty["raw"],ty["name"],"")
 for f in v["fields"]:
  assert base.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))==(f["raw"],(f["owner"],""),f["name"],f["sig"])
 c=v["ctor"];cm=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(c["token"],16))
 assert (cm[0],cm[4],cm[5],cm[7])==(c["raw"],c["name"],c["sig"],(c["owner"],""))
 assert (c["token"],c["name"])==("0x06005251",".ctor")
 f=w["forward_branch"];disp=struct.unpack_from("<i",body,0x487)[0]
 assert body[0x486]==0x38 and (disp,0x48b+disp)==(537,0x6a4)
 assert (f["instruction"],f["next"],f["displacement"],f["target"])==("0x0486","0x048B",537,"0x06A4")
 t=w["loop_tail"];lo=int(t["start"],16);hi=int(t["end_exclusive"],16)
 assert (lo,hi,hi-lo)==(0x69e,0x6b2,20) and body[lo:hi].hex()==t["hex"] and hashlib.sha256(body[lo:hi]).hexdigest()==t["sha256"]
 back=struct.unpack_from("<i",body,0x6ae)[0]
 assert body[0x6ad]==0x3f and (back,0x6b2+back)==(-551,0x48b)
 z=w["back_branch"];assert (z["instruction"],z["next"],z["displacement"],z["target"])==("0x06AD","0x06B2",-551,"0x048B")
 assert w["locals"]=={"anm":14,"index":15,"form":16}
 return {"source":"DLL-001","window_sha256":a["sha256"],"loop_tail_sha256":t["sha256"],"runtime_meaning":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_FORM_DISP_INFO_ARRAY_ENTRY_V1" and w["source_ids"]==["DLL-001"]
  print(json.dumps(check(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_DISP_INFO_ARRAY_ENTRY: PASS")
  return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_FORM_DISP_INFO_ARRAY_ENTRY: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
