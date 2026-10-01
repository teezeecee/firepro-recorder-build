#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Mine":(0x0030D1B0,324,"c461d4e1d4b587e58b3086f2eb88ae656d7147dbee555c6470ea7bb7a8243ffa"),"Down":(0x002E0584,807,"279517cb863c131495de999594e2eecb0ec3cfaada975d4215ee0efd7fb2b6f6")}
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
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Mine"]
 tok(c,0x0000,0x28,0x0600505D,"PlayerMan.GetInst")
 tok(c,0x0006,0x6F,0x06005065,"GetPlObj")
 tok(c,0x001A,0x7B,0x04005FEE,"Zone")
 tok(c,0x002A,0x7C,0x04005FAA,"PlPos")
 f32(c,0x0049,45.0,"angle45")
 f32(c,0x004E,0.0,"axis x");f32(c,0x0053,0.0,"axis y");f32(c,0x0058,1.0,"axis z")
 tok(c,0x0062,0x28,0x0A00067D,"Quaternion.AngleAxis")
 tok(c,0x0068,0x28,0x0A000053,"Quaternion multiply")
 for off,v in [(0x0075,3.6458330154418945),(0x0086,-3.6458330154418945),(0x0097,-6.4583330154418945),(0x00A8,-4.5833330154418945),(0x00BB,4.5833330154418945),(0x00CC,6.4583330154418945),(0x00DF,3.6458330154418945),(0x00F0,-3.6458330154418945),(0x0101,-6.4583330154418945),(0x0112,-4.5833330154418945),(0x0125,4.5833330154418945),(0x0136,6.4583330154418945)]:f32(c,off,v,"threshold "+hex(off))
 for off in [0x00B2,0x00D6,0x011C,0x0140]:
  if c[off:off+2]!=bytes([0x17,0x2A]):raise ProofError("true return "+hex(off))
 if c[0x0142:0x0144]!=bytes([0x16,0x2A]):raise ProofError("final false")
 tok(cs["Down"],0x023F,0x28,0x060050FC,"FACT-0049 caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Mine"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_IS_STEP_ON_MINE: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_IS_STEP_ON_MINE: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
