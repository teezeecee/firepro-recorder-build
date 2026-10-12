#!/usr/bin/env python3
"""FACT-0287 SHA-pinned original retail DLL-only LoadRSFFile and direct ancestor call edges."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_load_rsf_file_resource_route.summary.json"
EXPECTED=[
 ("literal_concat_resource_load_textasset",0x0000,0x0016,"72fa24047003281200000a28da06000a75e40000010a"),
 ("textasset_bytes_parse_rsf_and_leave",0x0016,0x002d,"066f4f01000a0b0207160416285f5200060cdd08000000"),
 ("exception_handler_null_fallback",0x002d,0x0035,"26140cdd00000000"),
 ("return_local_two",0x0035,0x0037,"082a")
]
MEMBERREFS={
 "0x0A000012":("Concat","f9050000e150060058490000",0x05f9,"00020e0e0e"),
 "0x0A0006DA":("Load","890700009f0c020095a90000",0x0789,"000112690e"),
 "0x0A00014F":("get_bytes","21070000f35b060032560000",0x0721,"20001d05")
}
TYPEREFS={
 "0x010000E4":("TextAsset","UnityEngine","0600e95b060080a60000",0x0006),
 "0x010000C2":("Object","System","0a001cb800000cae0000",0x000a)
}
def need(x,msg):
 if not x: raise RuntimeError(msg)
def memberref(pe,s,b,z,o,sb,bb,token):
 rid=token&0xffffff;pos=o[10]+(rid-1)*z[10];raw=pe[pos:pos+z[10]]
 coded,pos=base.rd(pe,pos,z[10]-s-b);nameidx,pos=base.rd(pe,pos,s);sigidx,pos=base.rd(pe,pos,b)
 return raw.hex(),coded,base.s_at(pe,sb,nameidx),base.blob(pe,bb,sigidx).hex()
def typeref(pe,s,z,o,sb,token):
 rid=token&0xffffff;pos=o[1]+(rid-1)*z[1];raw=pe[pos:pos+z[1]]
 scope,pos=base.rd(pe,pos,z[1]-2*s);nameidx,pos=base.rd(pe,pos,s);nsidx,pos=base.rd(pe,pos,s)
 return raw.hex(),scope,base.s_at(pe,sb,nameidx),base.s_at(pe,sb,nsidx)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"retail DLL size/SHA identity")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 _,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525C);body=md[9]
 need((md[0],md[1],md[4],md[5],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],m["signature_hex"],(m["owner"],"")),"original MethodDef raw identity/signature")
 need(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"original fat header")
 need((len(body),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["code_sha256"]),"complete original LoadRSFFile IL")
 need(len(m["segments"])==len(EXPECTED),"source IL region count")
 for seg,(name,lo,hi,hx) in zip(m["segments"],EXPECTED):
  need((seg["name"],int(seg["start_il"],16),int(seg["end_exclusive_il"],16),seg["il_hex"])==(name,lo,hi,hx),"segment identity "+name)
  need(body[lo:hi]==bytes.fromhex(hx),"original bounded IL "+name)
 need(b"".join(bytes.fromhex(seg[3]) for seg in EXPECTED)==body,"original 55-byte code wholly matched")
 us=w["dll"]["resource_literal"];token=0x700424FA;string_bytes=base.blob(pe,st["#US"][0],token&0xffffff)
 need(us["token"]=="0x700424FA" and body[1:5]==struct.pack("<I",token),"original ldstr token")
 need(string_bytes.hex()==us["raw_utf16le_and_marker_hex"] and string_bytes[:-1].decode("utf-16le")==us["text"]=="WrestlerAnimation/","original #US token/raw string")
 need(set(w["dll"]["memberrefs"])==set(MEMBERREFS),"original MemberRef count")
 for key,(name,row,coded,sig) in MEMBERREFS.items():
  a=w["dll"]["memberrefs"][key]
  need((a["token"],a["name"],a["metadata_row_hex"],int(a["class_coded"],16),a["signature_hex"])==(key,name,row,coded,sig),"MemberRef witness "+key)
  need(memberref(pe,s,b,z,o,sb,bb,int(key,16))==(row,coded,name,sig),"original MemberRef identity "+key)
 need(set(w["dll"]["typerefs"])==set(TYPEREFS),"original TypeRef count")
 for key,(name,namespace,row,scope) in TYPEREFS.items():
  a=w["dll"]["typerefs"][key]
  need((a["token"],a["name"],a["namespace"],a["metadata_row_hex"],int(a["resolution_scope_coded"],16))==(key,name,namespace,row,scope),"TypeRef witness "+key)
  need(typeref(pe,s,z,o,sb,int(key,16))==(row,scope,name,namespace),"original TypeRef identity "+key)
 eh=w["dll"]["exception_handler"]
 start=(md[8]+len(body)+3)&~3;raw=pe[start:start+16]
 need(eh["section_hex"]=="01100000000000002d2d0008c2000001" and raw.hex()==eh["section_hex"],"original EH metadata bytes")
 need((raw[0],raw[1],struct.unpack_from("<H",raw,4)[0],struct.unpack_from("<H",raw,6)[0],raw[8],struct.unpack_from("<H",raw,9)[0],raw[11],struct.unpack_from("<I",raw,12)[0])==(1,16,0,0,45,45,8,0x010000C2),"original EH clause exact fields")
 need((eh["try_start_il"],eh["try_length"],eh["handler_start_il"],eh["handler_length"],eh["catch_type_token"])==("0x0000",45,"0x002D",8,"0x010000C2"),"EH source witness")
 need(body[0x28]==body[0x30]==0xdd and 0x2d+struct.unpack_from("<i",body,0x29)[0]==0x35 and 0x35+struct.unpack_from("<i",body,0x31)[0]==0x35,"normal and fallback leave offsets")
 need(body[0x2d:0x35]==bytes.fromhex("26140cdd00000000") and body[0x35:0x37]==bytes.fromhex("082a"),"fallback null and return code")
 for edge in w["dll"]["call_chain"]:
  token=int(edge["token"],16);target=int(edge["target_token"],16);offset=int(edge["call_il"],16)
  node=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,token)
  need((node[0],node[1],node[4],node[7],len(node[9]),hashlib.sha256(node[9]).hexdigest())==(edge["method_row_hex"],int(edge["rva"],16),edge["name"],(edge["owner"],""),edge["code_size"],edge["code_sha256"]),"original call ancestor metadata "+edge["name"])
  need(edge["call_hex"]==(b"\x28"+struct.pack("<I",target)).hex() and node[9][offset:offset+5]==bytes.fromhex(edge["call_hex"]),"exact direct source caller "+edge["name"])
 expected=w["dll"]["previous_closed_parser"]
 tail=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x0600525F)[9]
 need((expected["token"],len(tail),hashlib.sha256(tail).hexdigest())==("0x0600525F",expected["code_bytes"],expected["code_sha256"]),"linked original parser identity")
 return {"fact_id":"FACT-0287","source":"DLL-001","wrapper_sha256":m["code_sha256"],"call_chain":[edge["name"] for edge in w["dll"]["call_chain"]],"literal":us["text"],"authored_resource_binding":"OPEN"}
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--dll",required=True);a=parser.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_LOAD_RSF_FILE_RESOURCE_ROUTE_V1" and w["source_ids"]==["DLL-001"],"witness provenance")
  print(json.dumps(verify(a.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_LOAD_RSF_FILE_RESOURCE_ROUTE: PASS")
  return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_LOAD_RSF_FILE_RESOURCE_ROUTE: FAIL",str(e))
  return 1
if __name__=="__main__":raise SystemExit(main())
