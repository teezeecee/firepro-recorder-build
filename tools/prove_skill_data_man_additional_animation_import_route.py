#!/usr/bin/env python3
"""FACT-0288: verify matching original DLL source for additional animation import."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_additional_animation_import_route.summary.json"
def need(q,m):
 if not q:raise RuntimeError(m)
def get_member(pe,s,b,z,o,sb,bb,tok):
 p=o[10]+((tok&0xffffff)-1)*z[10];raw=pe[p:p+z[10]]
 coded,p=base.rd(pe,p,z[10]-s-b);ni,p=base.rd(pe,p,s);si,p=base.rd(pe,p,b)
 return raw.hex(),coded,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex()
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"source DLL SHA")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525B);body=md[9]
 need((md[0],md[1],md[4],md[5],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],m["signature_hex"],(m["owner"],"")),"original MethodDef")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original method header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"])==(267,"f5966ee12b5c4065dcef8f0f00c3832f13a0a600a5914a2452c1f4e116f3506e"),"full original 267-byte IL")
 expected=[("enumerator_and_2000_key_gate",0x0000,0x0033),("bank_count_array_setup",0x0033,0x0065),("resource_name_construction",0x0065,0x00a9),("load_apply_and_inner_loop",0x00a9,0x00d7),("dictionary_add_and_move_next",0x00d7,0x00fc),("finally_dispose_and_ret",0x00fc,0x010b)]
 need(len(d["segments"])==len(expected),"segment count")
 for seg,(name,lo,hi) in zip(d["segments"],expected):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,lo,hi,body[lo:hi].hex()),"original source segment "+name)
 need(b"".join(bytes.fromhex(sg["il_hex"]) for sg in d["segments"])==body,"exact contiguous original body")
 need(set(d["fields"])=={"0x04000ED9","0x04000EDA","0x04000EB6","0x04007CF8"},"FieldDef set")
 for key,x in d["fields"].items():
  need(base.field(pe,s,b,z,o,sb,bb,fm,int(key,16))==(x["metadata_row_hex"],(x["owner"],""),x["name"],x["signature_hex"]),"original FieldDef "+key)
 need(len(d["memberrefs"])==10,"MemberRef count")
 for key,x in d["memberrefs"].items():
  need(get_member(pe,s,b,z,o,sb,bb,int(key,16))==(x["metadata_row_hex"],int(x["class_coded"],16),x["name"],x["signature_hex"]),"original MemberRef "+key)
 need(len(d["methoddef_callees"])==4,"callees count")
 for key,x in d["methoddef_callees"].items():
  target=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(key,16))
  need((target[0],target[1],target[4],target[7])==(x["metadata_row_hex"],int(x["rva"],16),x["name"],(x["owner"],"")),"original MethodDef callee "+key)
 need(set(d["user_strings"])=={"0x7008D506","0x700006E9","0x7008D510"},"resource literal tokens")
 for key,x in d["user_strings"].items():
  raw=base.blob(pe,st["#US"][0],int(key,16)&0xffffff)
  need(raw.hex()==x["raw_utf16le_and_marker_hex"] and raw[:-1].decode("utf-16le")==x["text"],"original #US token "+key)
 need(body[0x0024:0x0029]==bytes.fromhex("20d0070000"),"source key threshold")
 need(body[0x0087:0x008a]==bytes.fromhex("110418"),"original multi-file suffix threshold")
 need(body[0x00c7]==0xa2 and body[0x0109:0x010b]==bytes.fromhex("dc2a"),"array store and finally ret")
 need(len(d["branches"])==8,"branch count")
 for x in d["branches"]:
  loc=int(x["il"],16);op=int(x["opcode"],16);rel=x["rel_s32"];dst=int(x["target_il"],16)
  need(body[loc]==op and struct.unpack_from("<i",body,loc+1)[0]==rel and loc+5+rel==dst,"source branch "+x["name"])
 need(len(d["source_call_sites"])==4,"callsite count")
 for x in d["source_call_sites"]:
  p=int(x["il"],16);tok=int(x["target_token"],16)
  need(body[p:p+5]==bytes([int(x["opcode"],16)])+struct.pack("<I",tok),"source callsite "+x["name"])
 eh=d["exception_handler"];off=(md[8]+len(body)+3)&~3;raw=pe[off:off+16]
 need(raw.hex()==eh["section_hex"]=="0110000002001000ecfc000e00000000","original EH section")
 need((raw[0],raw[1],struct.unpack_from("<H",raw,4)[0],struct.unpack_from("<H",raw,6)[0],raw[8],struct.unpack_from("<H",raw,9)[0],raw[11],struct.unpack_from("<I",raw,12)[0])==(1,16,2,16,236,252,14,0),"original finally clause")
 need((eh["kind"],eh["data_size"],eh["flags"],eh["try_start_il"],eh["try_length"],eh["handler_start_il"],eh["handler_length"])==(1,16,2,"0x0010",236,"0x00FC",14),"EH witness")
 parent=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06005255)
 need(parent[9][0x001d:0x0022]==bytes.fromhex("285b520006"),"original Awake direct call")
 need((d["parent_boundary"]["target"],d["direct_child"]["methoddef"],d["direct_child"]["call_site_il"])==("0x0600525B","0x0600525C","0x00AD"),"source call chain")
 return {"fact_id":"FACT-0288","source":"DLL-001","full_method_sha":m["code_sha256"],"field_count":4,"direct_callee_count":4,"resource_payload_binding":"OPEN"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--dll",required=True);args=p.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_ADDITIONAL_ANIMATION_IMPORT_ROUTE_V1" and w["source_ids"]==["DLL-001"],"source provenance")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_ADDITIONAL_ANIMATION_IMPORT_ROUTE: PASS")
  return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_ADDITIONAL_ANIMATION_IMPORT_ROUTE: FAIL",str(e))
  return 1
if __name__=="__main__":raise SystemExit(main())
