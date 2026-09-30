#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Lookup":(0x0006A234,25,"fd2a546fcbc44dcd97c1376e5f5ba1802555f5b7f8c21d8ab3c123b3cf7fc0f0"),"SlotModifier":(0x002AEFFC,132,"224619b3628e2141649f4c24f24196c0d810edf2b2bbfeccd289e0822fb98012")}
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
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=mcode(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Lookup"]
 if c[0:2]!=bytes([0x02,0x16]):raise ProofError("negative gate args")
 br(c,0x0002,0x3F,0x000F,"slot < 0 null")
 if c[0x0007]!=0x02 or c[0x0008:0x000A]!=bytes([0x1F,0x5B]):raise ProofError("upper gate args")
 br(c,0x000A,0x3F,0x0011,"slot < 91 table")
 if c[0x000F:0x0011]!=bytes([0x14,0x2A]):raise ProofError("null return")
 tok(c,0x0011,0x7E,0x04000EE7,"SkillSlotDataTbl")
 if c[0x0016:0x0019]!=bytes([0x02,0x9A,0x2A]):raise ProofError("table index/return")
 tok(cs["SlotModifier"],0x000E,0x28,0x0600116D,"FACT-0024 caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Lookup"][2]},"raw_valid_range":[0,90]}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_SKILL_SLOT_DATA_LOOKUP: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_SKILL_SLOT_DATA_LOOKUP: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
