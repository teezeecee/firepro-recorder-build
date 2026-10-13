#!/usr/bin/env python3
"""FACT-0319 original-source verifier. Supply the original local DLL; no raw binary is stored in Git."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/dlc_uninstall_uninstall_source.summary.json"
def ck(v,msg):
 if not v: raise AssertionError(msg)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
 ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL identity")
 ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
 s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
 v=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=v[9]
 ck((v[0],v[1],v[4],v[5],v[7],pe[p.off(ss,v[1]):v[8]].hex())==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"]),m["header"]),"original MethodDef and header")
 ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"original 266-byte body")
 f=w["fields"][0];ck(p.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))==(f["row"],(f["owner"],f["namespace"]),f["name"],f["signature"]),"original FieldDef metadata")
 for site in f["sites"]: ck(il[site:site+5]==b"\x7b"+struct.pack("<I",int(f["token"],16)),"FieldDef source site")
 for c in w["callees"]:
  v=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(c["token"],16))
  ck((v[0],v[1],v[4],v[5],v[7],len(v[9]),hashlib.sha256(v[9]).hexdigest())==(c["row"],int(c["rva"],16),c["name"],c["signature"],(c["owner"],c["namespace"]),c["body_length"],c["body_sha256"]),"callee metadata/body "+c["token"])
  i=c["site"];ck(il[i:i+5]==b"\x28"+struct.pack("<I",int(c["token"],16)),"original call site")
 sw=w["switch"];i=sw["site"];n=struct.unpack_from("<I",il,i+1)[0];end=i+5+4*n
 ck((il[i],n,end)==(0x45,13,64),"original switch header")
 ck([struct.unpack_from("<i",il,i+5+4*k)[0] for k in range(n)]==sw["relative_deltas"],"original switch deltas")
 ck([end+struct.unpack_from("<i",il,i+5+4*k)[0] for k in range(n)]==sw["targets"],"original switch targets")
 for row in w["index_write_sites"]:
  j=row["field_site"];k=row["index"];ck(row["case_target"]==sw["targets"][k],"case-to-index identity")
  ck(il[j-1]==6 and il[j:j+5]==b"\x7b"+struct.pack("<I",0x0400650c),"original array field source")
  t=j+5
  if k<=8: ck(il[t]==0x16+k,"small case index");t+=1
  else: ck(il[t:t+2]==bytes([0x1f,k]),"large case index");t+=2
  ck(il[t:t+2]==b"\x16\x9e","original zero array store")
 for row in w["common_return_branches"]:
  i=row["site"];ck(il[i]==0x38 and i+5+struct.unpack_from("<i",il,i+1)[0]==w["ret_site"],"original common ret branch")
 ck(il[w["ret_site"]]==0x2a,"original return")
 return {"fact":"FACT-0319","original_source":"PASS","switch_cases":13,"case_writes":13,"callee_targets":3,"runtime_eligible":False}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);a=ap.parse_args()
 try:
  w=json.loads(W.read_text());ck(w["dataset_id"]=="DLL_DLC_UNINSTALL_UNINSTALL_SOURCE_V1" and w["source_ids"]==["DLL-001"],"witness identity")
  print(json.dumps(verify(a.dll,w),sort_keys=True));print("PROVE_DLC_UNINSTALL_UNINSTALL_SOURCE: PASS");return 0
 except Exception as e:
  print("PROVE_DLC_UNINSTALL_UNINSTALL_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
