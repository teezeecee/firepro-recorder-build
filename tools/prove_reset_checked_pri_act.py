#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Reset":(0x002FCE60,29,"875a2b35635251f80de9831dffb13bc94a030a2edd52a8b96e0496d68a46e9ff"),"SetLastSkill":(0x002DE4CF,26,"743d99df562a3f16f12fd7da264fa22386474eec9f6eee8061d83c0c690fb959")}
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
 c=cs["Reset"]
 if c[0:2]!=bytes([0x16,0x0A]):raise ProofError("index init")
 br(c,0x0002,0x38,0x0014,"initial branch to condition")
 if c[0x0007]!=0x02:raise ProofError("this load")
 tok(c,0x0008,0x7B,0x04006152,"checkedPriAct field")
 if c[0x000D:0x0010]!=bytes([0x06,0x16,0x9C]):raise ProofError("index/zero/stelem.i1")
 if c[0x0010:0x0014]!=bytes([0x06,0x17,0x58,0x0A]):raise ProofError("index increment")
 if c[0x0014:0x0017]!=bytes([0x06,0x1F,0x29]):raise ProofError("loop condition operands")
 br(c,0x0017,0x3F,0x0007,"signed blt loop")
 if c[0x001C]!=0x2A:raise ProofError("return")
 c=cs["SetLastSkill"]
 tok(c,0x0014,0x6F,0x06005007,"SetLastSkill callvirt")
 return {"dll_sha256":got,"method":{"code_size":len(cs["Reset"]),"code_sha256":M["Reset"][2]},"cleared_indices":[0,40]}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_RESET_CHECKED_PRI_ACT: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_RESET_CHECKED_PRI_ACT: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
