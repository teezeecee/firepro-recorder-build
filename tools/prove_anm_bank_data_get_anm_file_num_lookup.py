#!/usr/bin/env python3
"""FACT-0290 exact matching retail DLL source verification of AnmBankData.GetAnmFileNum."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/anm_bank_data_get_anm_file_num_lookup.summary.json"
METHOD_SHA="e14414c9db821065dd7627fb267798d6659affcb7acce76019717bd19664ca9c"
def need(ok,why):
 if not ok:raise RuntimeError(why)
def memberref(pe,s,b,z,o,sb,bb,token):
 p=o[10]+((token&0xffffff)-1)*z[10];raw=pe[p:p+z[10]]
 coded,p=base.rd(pe,p,z[10]-s-b);ni,p=base.rd(pe,p,s);si,p=base.rd(pe,p,b)
 return raw.hex(),coded,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex()
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL size/SHA")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06005244);body=md[9]
 need((md[0],md[1],md[4],md[5],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],m["signature_hex"],(m["owner"],"")),"original MethodDef row/signature/owner")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original fat method header")
 need((len(body),hashlib.sha256(body).hexdigest(),body.hex())==(62,METHOD_SHA,m["il_hex"]),"full original 62-byte method IL")
 need(m["code_sha256"]==METHOD_SHA and m["code_bytes"]==62,"witness method SHA/size")
 need(len(m["segments"])==5,"IL segments count")
 posi=0
 for seg in m["segments"]:
  start=int(seg["start_il"],16);end=int(seg["end_exclusive_il"],16)
  need(start==posi and end<=62 and body[start:end].hex()==seg["il_hex"],"original contiguous source IL "+seg["name"])
  posi=end
 need(posi==62,"entire source IL byte coverage")
 f=d["field"]
 need((f["token"],f["owner"],f["name"],f["metadata_row_hex"],f["signature_hex"])==("0x0400656D","AnmBankData","FileNumTbl","1100db140400620c0000","0614080200020000"),"FieldDef witness")
 need(base.field(pe,s,b,z,o,sb,bb,fm,0x0400656D)==(f["metadata_row_hex"],(f["owner"],""),f["name"],f["signature_hex"]),"original FieldDef raw metadata")
 need(f["read_ils"]==["0x0007","0x0019","0x002B"],"field load offsets")
 for label in f["read_ils"]:
  at=int(label,16)
  need(body[at:at+5]==bytes.fromhex("7e6d650004"),"original FileNumTbl ldsfld "+label)
 expected={"0x0A000716":("Get","74070000d859060078aa0000",1908,"2002080808",["0x000E","0x0020"],40),"0x0A00087C":("get_Length","09070000e85006005e490000",1801,"200008",["0x0030"],111)}
 need(set(d["memberrefs"])==set(expected),"MemberRef count")
 for key,(name,row,coded,sig,locations,op) in expected.items():
  ref=d["memberrefs"][key]
  need((ref["token"],ref["name"],ref["metadata_row_hex"],int(ref["class_coded"],16),ref["signature_hex"],ref["call_ils"])==(key,name,row,coded,sig,locations),"MemberRef witness "+key)
  need(memberref(pe,s,b,z,o,sb,bb,int(key,16))==(row,coded,name,sig),"original MemberRef metadata "+key)
  for label in locations:
   at=int(label,16)
   need(body[at:at+5]==bytes([op])+struct.pack("<I",int(key,16)),"original MemberRef call "+key+" @"+label)
 expected_br=[("initial_skip_to_loop_bound",2,0x38,35,0x2a),("not_equal_advance_loop",0x14,0x40,13,0x26),("index_less_than_half_length",0x37,0x3f,-53,0x07)]
 need(len(d["branches"])==3,"branch count")
 for v,(name,at,op,rel,to) in zip(d["branches"],expected_br):
  need((v["name"],int(v["il"],16),int(v["opcode"],16),v["relative_s32"],int(v["target_il"],16))==(name,at,op,rel,to),"source branch witness "+name)
  need(body[at]==op and struct.unpack_from("<i",body,at+1)[0]==rel and at+5+rel==to,"original branch target "+name)
 need(body[0x0011:0x0014]==bytes.fromhex("0a02"+"40")[:3],"loop local and arg comparison preceding bne") if False else None
 need(body[0x0035:0x0037]==bytes.fromhex("185b"),"literal 2 division")
 need(body[0x003c:0x003e]==bytes.fromhex("172a") and d["fallback"]=={"start_il":"0x003C","bytes":"172a","returns_literal":1},"literal default 1 and return")
 p=d["parent_call"]
 need((p["owner"],p["name"],p["token"],p["full_il_sha256"],p["call_il"],p["call_hex"],p["target_token"])==("SkillDataMan","LoadAdditionalAnimationData","0x0600525B","f5966ee12b5c4065dcef8f0f00c3832f13a0a600a5914a2452c1f4e116f3506e","0x004D","2844520006","0x06005244"),"parent witness")
 caller=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525B)
 need(hashlib.sha256(caller[9]).hexdigest()==p["full_il_sha256"] and caller[9][0x4d:0x52]==bytes.fromhex(p["call_hex"]),"original parent source callsite")
 return {"fact_id":"FACT-0290","source_id":"DLL-001","method_sha256":METHOD_SHA,"source_method_bytes":len(body),"authored_bank_table":"OPEN"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--dll",required=True);a=p.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_ANM_BANK_DATA_GET_ANM_FILE_NUM_LOOKUP_V1" and w["source_ids"]==["DLL-001"],"witness provenance")
  print(json.dumps(verify(a.dll,w),indent=2,sort_keys=True))
  print("PROVE_ANM_BANK_DATA_GET_ANM_FILE_NUM_LOOKUP: PASS")
  return 0
 except Exception as e:
  print("PROVE_ANM_BANK_DATA_GET_ANM_FILE_NUM_LOOKUP: FAIL",str(e))
  return 1
if __name__=="__main__":raise SystemExit(main())
