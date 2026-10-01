#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Force":(0x002E6C9C,49,"f62c7b101e9f67f9c7e8d3aaa1de4964a53b2669013d4574f0b8ecb2e9bc732c"),"Down":(0x002E0584,807,"279517cb863c131495de999594e2eecb0ec3cfaada975d4215ee0efd7fb2b6f6")}
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
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise ProofError("RVA unmapped")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Force"]
 tok(c,0x0002,0x7D,0x04006050,"standing flag clear")
 tok(c,0x0009,0x7D,0x04006051,"disable flag clear")
 tok(c,0x0010,0x28,0x06004ED8,"SetDownTime0")
 tok(c,0x0015,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x001A,0x7B,0x04002AD2,"MatchSetting")
 tok(c,0x001F,0x7B,0x040057E6,"isS1Rule")
 if c[0x0024]!=0x39 or 0x0029+struct.unpack_from("<i",c,0x0025)[0]!=0x002A:raise ProofError("isS1Rule branch")
 if c[0x0029]!=0x2A:raise ProofError("S1 return")
 tok(c,0x002B,0x28,0x06004F0D,"CalcDownTime")
 if c[0x0030]!=0x2A:raise ProofError("return")
 tok(cs["Down"],0x02AD,0x28,0x06004F0C,"FACT-0049 caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Force"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_FORCE_SET_DOWN_TIME: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_FORCE_SET_DOWN_TIME: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
