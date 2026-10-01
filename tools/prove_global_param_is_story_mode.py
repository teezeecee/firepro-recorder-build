#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0011382F
SIZE=10
CODE_SHA="421cdea7e302135e6671b62354bfa5d99562e3a6547b1d20d6aa9492bfa3fa8d"
CALLER_RVA=0x0006CA54
CALLER_SHA="f49006bbea8bcc23f4ac9019fc646d7fd2dc09edad531bc204b027a920bcc8c2"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 tok(c,0x0000,0x7E,0x04002862,"GlobalParam.m_SceneMode")
 if c[0x0005:0x0007]!=bytes([0x1F,0x0B]):raise E("raw11")
 if c[0x0007:0x0009]!=bytes([0xFE,0x01]):raise E("ceq")
 if c[0x0009]!=0x2A:raise E("ret")
 tok(cc,0x0058,0x28,0x06001FC1,"FACT-0117 caller")
 print("PROVE_GLOBAL_PARAM_IS_STORY_MODE: PASS")
if __name__=="__main__":main()
