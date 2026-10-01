#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
CALLER_RVA=0x00322268
CALLER_SHA="2e0905ada32d6f97c3a3ac37f28bb0722b6084a109618070cf1dfc1ea1fb4733"
FACTORIES=[
 (0x00322208,36,"6bf3b32bde5c0e41ede808a7df79d384f18e7aa4cb00181ed96c4495a8a69082",0x11001200,0x060074E9,(0x0400C23D,0x0400C23F,0x0400C240,0x0400C241)),
 (0x00322238,36,"350a54533b1c76c5c5a5d7259e377d8aa3b1e1cf2aeb16042332cc6aa01bedb5",0x11001201,0x060074EF,(0x0400C245,0x0400C247,0x0400C248,0x0400C249))
]
CTORS=[
 (0x00324C53,0x060074E9),
 (0x00324D53,0x060074EF)
]
CTOR_SHA="5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def check_factory(pe,ss,row):
 rva,size,sha,local_sig,ctor,fields=row;m=method(pe,ss,rva);c=m["code"]
 if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E("factory body")
 if m["max_stack"]!=2 or m["local_sig"]!=local_sig:raise E("factory header")
 tok(c,0x0000,0x73,ctor,"factory newobj")
 if c[0x0005:0x0008]!=bytes([0x0A,0x06,0x02]):raise E("fn args")
 tok(c,0x0008,0x7D,fields[0],"fn field")
 if c[0x000D:0x000F]!=bytes([0x06,0x03]):raise E("system_sound args")
 tok(c,0x000F,0x7D,fields[1],"system_sound field")
 if c[0x0014:0x0016]!=bytes([0x06,0x05]):raise E("onLoad args")
 tok(c,0x0016,0x7D,fields[2],"onLoad field")
 if c[0x001B:0x001D]!=bytes([0x06,0x04]):raise E("bStart args")
 tok(c,0x001D,0x7D,fields[3],"bStart field")
 if c[0x0022:0x0024]!=bytes([0x06,0x2A]):raise E("iterator return")
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 for row in FACTORIES:check_factory(pe,ss,row)
 for rva,tokid in CTORS:
  c=method(pe,ss,rva)["code"]
  if len(c)!=7 or hashlib.sha256(c).hexdigest()!=CTOR_SHA:raise E("ctor body")
  if c[0]!=0x02:raise E("ctor this")
  tok(c,0x0001,0x28,0x0A0000EF,"System.Object..ctor")
  if c[0x0006]!=0x2A:raise E("ctor ret")
 cc=method(pe,ss,CALLER_RVA)["code"]
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 tok(cc,0x00A7,0x28,0x06005294,"FACT-0111 CoChange_BGMandPlay")
 tok(cc,0x007E,0x28,0x06005295,"FACT-0111 CoChange_BGMandPlay_FromAssetBundle")
 print("PROVE_MENU_SOUND_THEME_COROUTINE_FACTORIES: PASS")
if __name__=="__main__":main()
