#!/usr/bin/env python3
"""FACT-0265 source-byte replay. Original retail DLL is an external input."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/CAP-R6-001/skill_data_man_packed_skill_loop.summary.json"
def check(x,msg):
 if not x:raise RuntimeError(msg)
def verify(path,w):
 p=Path(path).read_bytes();d=w["dll"];m=d["method"]
 check(len(p)==d["size_bytes"] and hashlib.sha256(p).hexdigest()==d["sha256"],"DLL identity")
 ss,q=base.secs(p);st,hs,rows,a=base.mdstreams(p,ss,q)
 s,b,ix,z,o=base.tables(p,st,hs,rows,a);sb=st["#Strings"][0];bb=st["#Blob"][0]
 _,owners=base.owner_maps(p,rows,s,ix,z,o,sb)
 row,rva,imp,flags,name,sig,plist,owner,start,body=base.method(p,ss,s,b,ix,z,o,sb,bb,owners,0x06005257)
 check((row,rva,imp,flags,name,sig,owner)==(m["methoddef_row_hex"],int(m["rva"],16),0,0x81,m["name"],m["signature_blob_hex"],(m["owner"],"")),"MethodDef")
 check(p[base.off(ss,rva):start].hex()==m["header_hex"],"header")
 check(len(body)==354 and hashlib.sha256(body).hexdigest()==m["code_sha256"],"IL original SHA")
 para=o[8]+(plist-1)*z[8];idx,_=base.rd(p,para+4,s)
 check(p[para:para+z[8]].hex()==m["parameter_row_hex"] and base.s_at(p,sb,idx)==m["parameter_name"],"Param")
 check(body[0:9].hex()=="0375cf02001b0a160b","object TypeSpec entry")
 check(body[0x000E:0x0012].hex()=="071e5a0c","raw *8 stride")
 for off,val in [(0x42,2675),(0x7c,2675),(0xb0,4188),(0x157,2000)]:
  check(body[off]==0x20 and struct.unpack_from("<i",body,off+1)[0]==val,"literal "+hex(off))
 for off,op,tgt in [(0x34,0x3f,0x3e),(0x81,0x3c,0xab),(0xb5,0x3f,0xe),(0x15c,0x3f,0xc2)]:
  check(body[off]==op and off+5+struct.unpack_from("<i",body,off+1)[0]==tgt,"branch "+hex(off))
 sites=[(0x4d,0x28,0x06005268),(0x5b,0x6f,0x06001163),(0x69,0x7b,0x04007cf7),(0x75,0x28,0x0600525f),
 (0x8d,0x6f,0x06001163),(0xa6,0x6f,0x06001166),(0xc9,0x6f,0x06001163),(0xdf,0x6f,0x06001164),
 (0xe8,0x7b,0x04000eb6),(0xfe,0x28,0x06005244),(0x105,0x7e,0x040085c3),(0x111,0x8d,0x02000a6a),
 (0x125,0x7b,0x04007cf7),(0x141,0x7b,0x04007cf8),(0x14a,0x6f,0x0a000f99)]
 for off,op,tok in sites:
  check(body[off]==op and struct.unpack_from("<I",body,off+1)[0]==tok,"original token "+hex(off))
 for child in d["methoddef_children"]:
  cur=base.method(p,ss,s,b,ix,z,o,sb,bb,owners,int(child["token"],16))
  check((cur[4],cur[7],len(cur[9]),hashlib.sha256(cur[9]).hexdigest())==
   (child["name"],(child["owner"],""),child["body_size"],child["body_sha256"]),"raw child "+child["token"])
 caller=base.method(p,ss,s,b,ix,z,o,sb,bb,owners,0x06005256)
 check(caller[9][0x1f:0x24].hex()=="2857520006" and
  hashlib.sha256(caller[9]).hexdigest()==d["direct_caller"]["body_sha256"],"caller")
 return {"source":"DLL-001","code_size":len(body),"code_sha256":m["code_sha256"],"first_raw_bound":4188,"second_raw_bound":2000,"source_child_count":len(d["methoddef_children"])}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);a=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  check(w["dataset_id"]=="DLL_SKILL_DATA_MAN_PACKED_SKILL_LOOP_V1","witness")
  print(json.dumps(verify(a.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_PACKED_SKILL_LOOP: PASS");return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_PACKED_SKILL_LOOP: FAIL",e);return 1
if __name__=="__main__":raise SystemExit(main())
