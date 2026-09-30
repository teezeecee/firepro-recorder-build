#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Clear":(0x002A4DFD,29,"12183b4682dd4873916a8e3a0305c01ed4c53de737a481b94c7f3c47ee46c1c5"),"Set":(0x002A4E1B,49,"f5ede8840d753fddbc5e58b18de45f8b9f3afefc5efcd4f1fd3666a6bd9f2476"),"ApplyDamage":(0x002AF188,1641,"6ecc8c9b5e71235fcbde51d1ca3d8baafd5b4d713abc298947b6848627d419b5")}
F=[0x040056CB,0x040056CC,0x040056CD,0x040056CE]
class ProofError(RuntimeError):pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1024*1024),b""):h.update(x)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise ProofError("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def rvaoff(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise ProofError("RVA unmapped")
def mcode(pe,ss,rva):
 o=rvaoff(ss,rva);fb=pe[o]
 if fb&3==2:h=1;n=fb>>2
 elif fb&3==3:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 else:raise ProofError("bad IL header")
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=mcode(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Clear"]
 for i,t in enumerate(F):
  o=i*7
  if c[o:o+2]!=bytes([0x02,0x15]):raise ProofError("Clear prefix "+str(i))
  tok(c,o+2,0x7D,t,"Clear field "+str(i))
 if c[0x001C]!=0x2A:raise ProofError("Clear ret")
 c=cs["Set"]
 for i,t in enumerate(F):
  o=i*12
  if c[o:o+2]!=bytes([0x02,0x03]):raise ProofError("Set prefix "+str(i))
  tok(c,o+2,0x7B,t,"Set source field "+str(i))
  tok(c,o+7,0x7D,t,"Set target field "+str(i))
 if c[0x0030]!=0x2A:raise ProofError("Set ret")
 c=cs["ApplyDamage"]
 for off,t in [(0x05CD,0x060048D2),(0x05E0,0x060048D2),(0x060A,0x060048D1)]:
  tok(c,off,0x6F,t,"ApplyDamage FinishMoveInfo caller "+hex(off))
 return {"dll_sha256":got,"methods":{"Clear":{"code_size":len(cs["Clear"]),"code_sha256":M["Clear"][2]},"Set":{"code_size":len(cs["Set"]),"code_sha256":M["Set"][2]}}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_FINISH_MOVE_INFO_HELPERS: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_FINISH_MOVE_INFO_HELPERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
