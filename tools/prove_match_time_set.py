#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Leaf":(0x002A7AF0,37,"94a90dfec6b4dda72ec1c11c69106555c2e093589c42bf30bfa37c5351f613d5"),"Caller":(0x002A9904,261,"f204671841365e78a2dfef78bb7a34a0c483ee30ac13d388b9b28b22cd5f17e9")}
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 if c[0x0000:0x0002]!=bytes([0x02,0x03]):raise E("min args")
 tok(c,0x0002,0x7B,0x0400572E,"min source")
 tok(c,0x0007,0x7D,0x0400572E,"min target")
 if c[0x000C:0x000E]!=bytes([0x02,0x03]):raise E("sec args")
 tok(c,0x000E,0x7B,0x0400572F,"sec source")
 tok(c,0x0013,0x7D,0x0400572F,"sec target")
 if c[0x0018:0x001A]!=bytes([0x02,0x03]):raise E("frm args")
 tok(c,0x001A,0x7B,0x04005730,"frm source")
 tok(c,0x001F,0x7D,0x04005730,"frm target")
 if c[0x0024]!=0x2A:raise E("ret")
 tok(cs["Caller"],0x00E2,0x6F,0x06004905,"FACT-0097 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"copies":["min","sec","frm"]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_MATCH_TIME_SET: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_MATCH_TIME_SET: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
