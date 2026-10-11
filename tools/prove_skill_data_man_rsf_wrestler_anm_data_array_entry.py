#!/usr/bin/env python3
"""FACT-0275: original RSF WrestlerAnmData array allocation/entry, strict IL and metadata."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_wrestler_anm_data_array_entry.summary.json"
def need(ok,why):
 if not ok:raise RuntimeError(why)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"exact original retail DLL")
 sections,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,sections,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,sections,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"raw original ParseRSFData method")
 need(pe[base.off(sections,md[1]):md[8]].hex()==m["header_hex"] and len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"whole original method IL")
 lo=int(a["start_il"],16);hi=int(a["end_exclusive_il"],16)
 need((lo,hi,hi-lo)==(0x39a,0x3cc,50) and hashlib.sha256(body[lo:hi]).hexdigest()==a["source_sha256"],"exact contiguous 50-byte source")
 expected=[
 ("allocate_anmData_array_from_anmNum",0x39a,0x3ab,"07077b547c00048d6e0a00027d7a7c0004"),
 ("initialize_index_and_jump_to_guard",0x3ab,0x3b3,"16130d3805030000"),
 ("new_constructor_and_stelem_ref",0x3b3,0x3c1,"077b7a7c0004110d734e520006a2"),
 ("reload_array_entry_to_local14",0x3c1,0x3cc,"077b7a7c0004110d9a130e")]
 need(len(a["segments"])==4,"four source spans")
 at=lo
 for x,(name,begin,end,hx) in zip(a["segments"],expected):
  need((x["name"],int(x["start_il"],16),int(x["end_exclusive_il"],16),x["source_hex"])==(name,begin,end,hx) and begin==at and body[begin:end]==bytes.fromhex(hx),"source span "+name)
  at=end
 need(at==hi,"no omitted IL bytes")
 typedef=a["element_type"];row=base.typedef(pe,rows,s,ix,z,o,sb,int(typedef["typedef_token"],16)&0xffffff)
 need((row[0],row[1],row[2])==(typedef["metadata_row_hex"],typedef["name"],typedef["namespace"])==("0120100039810000000000000903937c4e52","WrestlerAnmData",""),"original type allocation token/row")
 for fd in a["source_fields"]:
  row=base.field(pe,s,b,z,o,sb,bb,fm,int(fd["token"],16))
  need(row==(fd["metadata_row_hex"],(fd["owner"],""),fd["name"],fd["signature_hex"]),"original source field "+fd["name"])
 need([(x["token"],x["name"]) for x in a["source_fields"]]==[("0x04007C54","anmNum"),("0x04007C7A","anmData")],"original source field mapping")
 co=a["constructor"];mo=base.method(pe,sections,s,b,ix,z,o,sb,bb,owners,int(co["token"],16))
 need((mo[0],mo[4],mo[5],mo[7])==(co["metadata_row_hex"],co["name"],co["signature_hex"],(co["owner"],"")),"original WrestlerAnmData constructor identity")
 need((co["token"],co["signature_hex"])==("0x0600524E","200001"),"expected constructor token/signature")
 br=a["forward_branch"]
 need((br["opcode"],br["instruction_il"],br["next_il"],br["target_il"],br["displacement"])==("br","0x03AE","0x03B3","0x06B8",773),"witness original forward guard edge")
 forward=struct.unpack_from("<i",body,0x3af)[0]
 need(body[0x3ae]==0x38 and forward==773 and 0x3b3+forward==0x6b8,"actual original br forward")
 tail=a["loop_tail"];tl=int(tail["start_il"],16);te=int(tail["end_exclusive_il"],16)
 need((tl,te,te-tl)==(0x6b3,0x6c5,18) and body[tl:te].hex()==tail["source_hex"] and hashlib.sha256(body[tl:te]).hexdigest()==tail["source_sha256"],"original far increment/guard IL")
 displacement=struct.unpack_from("<i",body,0x6c1)[0]
 need(body[0x6c0]==0x3f and displacement==-786 and 0x6c5+displacement==0x3b3,"original backward blt guard edge")
 need((tail["back_edge_displacement"],tail["back_edge_next_il"],tail["back_edge_target_il"])==(-786,"0x06C5","0x03B3"),"witness loop tail target")
 need((a["array_length_source"],a["array_entry_index_local"],a["array_entry_reference_local"])==("SkillData.anmNum (not a literal count)",13,14),"source variable/local identities")
 return {"source":"DLL-001","method_sha256":m["code_sha256"],"source_window_sha256":a["source_sha256"],"loop_tail_sha256":tail["source_sha256"],"created_type":"WrestlerAnmData[]","destination":"SkillData.anmData","branch_targets":["0x06B8","0x03B3"],"runtime_meaning":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_WRESTLER_ANM_DATA_ARRAY_ENTRY_V1" and w["source_ids"]==["DLL-001"],"witness source identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_WRESTLER_ANM_DATA_ARRAY_ENTRY: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_WRESTLER_ANM_DATA_ARRAY_ENTRY: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
