#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x0028FE76,54,"aeedc6c70baddc6ef42cd4c445d568061fdc8a73a18464494aad0e9062279520"),
 "Caller":(0x00309428,156,"e71d1708191a0dc125367efbaa8adb8c280f8e1068cf6ae26ea320a98d482d8b")
}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 if c[0:2]!=bytes([0x02,0x03]):raise E("this/nLevel")
 tok(c,0x0002,0x7D,0x040054CB,"CheerLevel_Base initial store")
 if c[0x0007]!=0x02:raise E("upper this")
 tok(c,0x0008,0x7B,0x040054CB,"upper read")
 if c[0x000D]!=0x1A:raise E("upper raw4")
 br(c,0x000E,0x3E,0x001A,"upper <=4")
 if c[0x0013:0x0015]!=bytes([0x02,0x1A]):raise E("upper clamp args")
 tok(c,0x0015,0x7D,0x040054CB,"upper clamp store")
 if c[0x001A]!=0x02:raise E("lower this")
 tok(c,0x001B,0x7B,0x040054CB,"lower read")
 if c[0x0020:0x0022]!=bytes([0x1F,0xFC]):raise E("lower raw -4")
 br(c,0x0022,0x3C,0x002F,"lower >= -4")
 if c[0x0027:0x002A]!=bytes([0x02,0x1F,0xFC]):raise E("lower clamp args")
 tok(c,0x002A,0x7D,0x040054CB,"lower clamp store")
 if c[0x002F]!=0x02:raise E("CalcCheerLevel this")
 tok(c,0x0030,0x28,0x060047E0,"FACT-0083 CalcCheerLevel")
 if c[0x0035]!=0x2A:raise E("ret")
 cc=cs["Caller"]
 tok(cc,0x006D,0x6F,0x060047D8,"FACT-0093 caller")
 if cc[0x006C]!=0x1A:raise E("FACT-0093 raw4")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"clamp":[-4,4],"fact_0093_raw_argument":4}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_AUDIENCE_SET_BASE_CHEER_LEVEL: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_AUDIENCE_SET_BASE_CHEER_LEVEL: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
