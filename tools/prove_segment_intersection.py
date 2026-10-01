#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Cross":(0x002B7C10,32,"d5ac4557f63717bfd9e57b204629c1e68dee69af19ff1f8c5842fb5667808c6f"),"Inter":(0x002B7CC0,416,"3ecf11f34c121c71dd42aa6aa5ea214ce1417008a01246410a71ef504a537f76"),"Caller":(0x0030CF88,538,"342c92172a4c47371d07312bf9b8d7bec1b5d2cd2cbe9019255e8282ee26b59f")}
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
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Cross"]
 tok(c,0x0002,0x7B,0x0A000059,"a.x");tok(c,0x0009,0x7B,0x0A00005A,"b.y")
 tok(c,0x0011,0x7B,0x0A00005A,"a.y");tok(c,0x0018,0x7B,0x0A000059,"b.x")
 if c[0x001D:0x0020]!=bytes([0x5A,0x59,0x2A]):raise ProofError("cross mul/sub/ret")
 c=cs["Inter"]
 tok(c,0x0001,0x28,0x0A00008B,"Vector2.zero")
 for off in [0x0065,0x00C5,0x0134]:tok(c,off,0x28,0x06004A8E,"CrossProduct "+hex(off))
 br(c,0x00D3,0x44,0x00DA,"first blt.un")
 if c[0x00D8:0x00DA]!=bytes([0x16,0x2A]):raise ProofError("first false return")
 br(c,0x014D,0x44,0x0154,"second blt.un")
 if c[0x0152:0x0154]!=bytes([0x16,0x2A]):raise ProofError("second false return")
 if c[0x0154:0x015E]!=bytes([0x11,0x04,0x11,0x04,0x11,0x05,0x59,0x5B,0x13,0x06]):raise ProofError("interpolation scalar")
 tok(c,0x015F,0x0F,0x01,"dummy") if False else None
 if c[0x019E:0x01A0]!=bytes([0x17,0x2A]):raise ProofError("true return")
 tok(cs["Caller"],0x0214,0x28,0x06004A92,"FACT-0053 caller")
 return {"dll_sha256":got,"methods":{"Cross":{"code_size":len(cs["Cross"]),"code_sha256":M["Cross"][2]},"Inter":{"code_size":len(cs["Inter"]),"code_sha256":M["Inter"][2]}}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_SEGMENT_INTERSECTION: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_SEGMENT_INTERSECTION: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
