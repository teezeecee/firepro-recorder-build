#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"; DLL_SIZE=8171008
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"; EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
T=0x0600505D; RVA=0x00304880; ROW="80483000000096003b7f0800b8d40200f73a"; SIG="000012a818"; FLAGS=0x0096
BODY=bytes.fromhex("7efa6100042a"); SHA="592555acaf96cbd806fb44a0dfd643c83f27267edcf79fe7ab57ec6c0457b1ff"
FIELD=0x040061FA; FIELD_ROW="160006220100cf380000"; FIELD_SIG="0612a818"
REF_COUNT=171; CALLER_COUNT=102
REF_DIGEST="fd83acc3062a77a8dee1dde7084c989511249701cff57fb1100cb89a6446400c"
CALLER_DIGEST="bc51127accf19d7f10201296d4ab08f4904ba0cc486761926070068406e95ff9"
WEAPON=0x06006ABA; WEAPON_SHA="3aa49b941ea49de68211c6b8bd98672b796ea36dc5eb99deeae75ef911aa737d"
SYNC=0x06004B48; SYNC_SHA="ac9ee661178e8c57fa83c0572a6bc65d650c99c1aff55185cc942f5e5c52c89d"

class E(RuntimeError): pass

def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for c in iter(lambda:f.read(1048576),b""): h.update(c)
 return h.hexdigest()

def mmeta(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff; p=o[6]+(rid-1)*z[6]; raw=pe[p:p+z[6]]
 rva=struct.unpack_from("<I",raw)[0]; impl=struct.unpack_from("<H",raw,4)[0]; flags=struct.unpack_from("<H",raw,6)[0]
 q=p+8; ni,q=ov.base.rd(pe,q,s); si,q=ov.base.rd(pe,q,b); plist,q=ov.base.rd(pe,q,ix(8))
 start,body=ov.base.meth(pe,ss,rva) if rva else (None,b"")
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body

def all_refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
 needle=struct.pack("<I",T); out=[]
 pats=[(bytes([0x28])+needle,"call"),(bytes([0x6f])+needle,"callvirt"),(bytes([0x73])+needle,"newobj"),(bytes([0x27])+needle,"jmp"),(b"\xfe\x06"+needle,"ldftn"),(b"\xfe\x07"+needle,"ldvirtftn")]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid
  raw,rva,impl,flags,name,sig,plist,owner,start,body=mmeta(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not body: continue
  for pat,opname in pats:
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0: break
    out.append({
     "caller_type":owner[0] if owner else None,
     "caller_namespace":owner[1] if owner else None,
     "caller_method":name,
     "caller_token":f"0x{tok:08X}",
     "caller_rva":f"0x{rva:08X}",
     "caller_code_size":len(body),
     "caller_code_sha256":hashlib.sha256(body).hexdigest(),
     "call_il":f"0x{x:04X}",
     "opcode":opname
    })
    pos=x+1
 out.sort(key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
 return out

def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E("DLL identity")
 ss,q=ov.base.secs(pe); st,hs,rows,tp=ov.base.mdstreams(pe,ss,q); s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp)
 sb=st["#Strings"][0]; bb=st["#Blob"][0]; fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,name,sig,plist,owner,start,body=mmeta(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,"GetInst",SIG,("PlayerMan","")): raise E("method metadata")
 ho=ov.base.off(ss,RVA)
 if pe[ho]!=0x1A: raise E("tiny header")
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E("body")
 if body[0]!=0x7e or struct.unpack_from("<I",body,1)[0]!=FIELD or body[5]!=0x2a: raise E("exact flow")
 fr=FIELD&0xffffff; fp=o[4]+(fr-1)*z[4]; q2=fp+2; ni,q2=ov.base.rd(pe,q2,s); si,_=ov.base.rd(pe,q2,b)
 if pe[fp:fp+z[4]].hex()!=FIELD_ROW or fm.get(fr)!=("PlayerMan","") or ov.base.s_at(pe,sb,ni)!="inst" or ov.base.blob(pe,bb,si).hex()!=FIELD_SIG: raise E("field")
 refs=all_refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(refs)!=REF_COUNT or len({x["caller_token"] for x in refs})!=CALLER_COUNT: raise E("reference counts")
 if {x["opcode"] for x in refs}!={"call"}: raise E("reference opcode surface")
 digest=hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()
 if digest!=REF_DIGEST: raise E("reference-map digest "+digest)
 callers=sorted({x["caller_token"] for x in refs})
 cd=hashlib.sha256(("\n".join(callers)+"\n").encode()).hexdigest()
 if cd!=CALLER_DIGEST: raise E("caller-set digest "+cd)
 wr=[x for x in refs if x["caller_token"]==f"0x{WEAPON:08X}"]
 sr=[x for x in refs if x["caller_token"]==f"0x{SYNC:08X}"]
 if len(wr)!=1 or wr[0]["call_il"]!="0x0000" or wr[0]["caller_code_sha256"]!=WEAPON_SHA: raise E("FACT-0201 boundary")
 if [x["call_il"] for x in sr]!=["0x0051","0x0164"] or any(x["caller_code_sha256"]!=SYNC_SHA for x in sr): raise E("IsSyncInputData boundary")
 return {"code_size":6,"code_sha256":SHA,"direct_reference_count":len(refs),"direct_caller_method_count":len(callers),"reference_map_sha256":digest}

def verify_r6(path):
 if sh(path)!=R6_SHA: raise E("R6 identity")
 wanted={"PlayerMan.GetInst":0,"Network.IsSyncInputData":0,"Weapon.Update_Equipped":0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip(): raise E("CRC")
  names=[n for n in zf.namelist() if Path(n).name=="event_trace.tsv"]
  if len(names)!=1: raise E("event trace count")
  bts=zf.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA: raise E("event identity")
  for row in csv.DictReader(io.StringIO(bts.decode("utf-8-sig")),delimiter="\t"):
   if row["method"] in wanted: wanted[row["method"]]+=1
 if any(wanted.values()): raise E("R6 boundary "+repr(wanted))
 return dict(wanted,promoted_as_evidence=False)

def main():
 a=argparse.ArgumentParser(); a.add_argument("--dll",required=True); a.add_argument("--r6",required=True); x=a.parse_args()
 try:
  print(json.dumps({"dll":verify_dll(x.dll),"r6":verify_r6(x.r6)},indent=2,sort_keys=True))
  print("PROVE_PLAYERMAN_GET_INST: PASS"); return 0
 except Exception as e:
  print("PROVE_PLAYERMAN_GET_INST: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
