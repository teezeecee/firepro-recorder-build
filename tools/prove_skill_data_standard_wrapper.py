#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Wrap":(0x0031FF20,14,"9db7aaaf1198a49f3fd4637000dab60fa02b6ede3a444f5dfb2a09e7e6e844f9"),"Update":(0x00307E94,415,"5d41c826c5bc4929960746b1b03abdd389b4911c89ec01a48fda0eba6e6c9e4a")}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
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
 c=cs["Wrap"]
 if c[0]!=0x02:raise E("this")
 if c[1]!=0x20 or struct.unpack_from("<i",c,2)[0]!=2675:raise E("raw offset 2675")
 if c[6:9]!=bytes([0x03,0x58,0x28]):raise E("skill_idx add call prefix")
 if struct.unpack_from("<I",c,9)[0]!=0x06005262:raise E("GetSkillData token")
 if c[13]!=0x2A:raise E("ret")
 tok(cs["Update"],0x0023,0x6F,0x06005264,"FACT-0070 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Wrap"][2]},"raw_offset":2675,"callee":"0x06005262"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_SKILL_DATA_STANDARD_WRAPPER: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_SKILL_DATA_STANDARD_WRAPPER: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
