#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "GetInst":(0x0030A47D,6,"9520016c102a2a51bd00c0108de13b24734f1b686f000e2460083dd39da009ee"),
 "GetRefereeObj":(0x0030A4C3,9,"aa2a417db5ba1940541d91f5a98fe26ec59230af147fdb4dd2e768ca0dad1e4d"),
 "PlayRefereeSE":(0x00321688,77,"43db6ad4797e97ed994bdc3c50bd925b35592f129148bd42103009de2d51b645")
}
class E(RuntimeError): pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""): h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0": raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0]; z=struct.unpack_from("<H",pe,q+20)[0]; s=q+24+z; out=[]
 for i in range(n):
  o=s+i*40; vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz: o=rp+rva-va; break
 else: raise E("rva")
 b=pe[o]
 if b&3==2: h=1; n=b>>2
 else:
  fs=struct.unpack_from("<H",pe,o)[0]; h=(fs>>12)*4; n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t: raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA: raise E("dll")
 pe=Path(path).read_bytes(); ss=secs(pe); cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha: raise E(n+" body")
  cs[n]=c
 c=cs["GetInst"]
 tok(c,0x0000,0x7E,0x040062DC,"RefereeMan.inst")
 if c[0x0005]!=0x2A: raise E("GetInst ret")
 c=cs["GetRefereeObj"]
 if c[0x0000]!=0x02: raise E("GetRefereeObj this")
 tok(c,0x0001,0x7B,0x040062DE,"RefereeObj field")
 if c[0x0006:0x0009]!=bytes([0x16,0x9A,0x2A]): raise E("RefereeObj[0] return")
 c=cs["PlayRefereeSE"]
 tok(c,0x0009,0x28,0x060050B2,"FACT-0064 GetInst caller")
 tok(c,0x000E,0x6F,0x060050B6,"FACT-0064 GetRefereeObj caller")
 return {"dll_sha256":DLL_SHA,"methods":{"GetInst":M["GetInst"][2],"GetRefereeObj":M["GetRefereeObj"][2]},"caller":"FACT-0064"}
def main():
 a=argparse.ArgumentParser(); a.add_argument("--dll",required=True); a.add_argument("--out"); x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out: Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True)); print("PROVE_REFEREE_OBJECT_LOOKUPS: PASS"); return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_OBJECT_LOOKUPS: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
