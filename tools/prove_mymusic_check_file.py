#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x001AE7A4,25,"193b347ba039064fe416b7d3c34758af6401a2ead6f5c45046904e0a29646877"),
 "Caller":(0x002A95D8,195,"57fe61387e5df262b4c752819960c309b4a48a1a2299a231f8f5199a6e69eeb3")
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
 tok(c,0x0000,0x7E,0x04003903,"Root_DirectotyPath")
 if c[0x0005]!=0x02:raise E("argument")
 tok(c,0x0006,0x28,0x0A000012,"memberref 0x0A000012")
 tok(c,0x000B,0x28,0x0A000216,"memberref 0x0A000216")
 br(c,0x0010,0x39,0x0017,"Boolean false branch")
 if c[0x0015:0x0019]!=bytes([0x17,0x2A,0x16,0x2A]):raise E("Boolean returns")
 tok(cs["Caller"],0x0098,0x28,0x06002C1E,"FACT-0096 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"fact_0096_call_il":"0x0098"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_MYMUSIC_CHECK_FILE: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_MYMUSIC_CHECK_FILE: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
