#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00314983
SIZE=39
CODE_SHA="dcca7695b47672ce7825fed3223764f312476b6d900da9aa66b929a54916780b"
CALLER_RVA=0x003149AB
CALLER_SHA="6ae14bc58bd6ce5fef923aed7dc39a940d5975700065175c076beda7f3ff143e"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def token(c,o,op,t):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(hex(o))
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 token(c,0x0000,0x7E,0x04004856)
 if c[0x0005]!=0x18 or c[0x0006]!=0x3C or 0x000B+struct.unpack_from("<i",c,0x0007)[0]!=0x001C:raise E("branch")
 token(c,0x000B,0x7E,0x040064EC);token(c,0x0010,0x7B,0x0400650F);token(c,0x0015,0x7E,0x04004856)
 if c[0x001A:0x001C]!=bytes([0x9A,0x2A]):raise E("array")
 token(c,0x001C,0x7E,0x0400497D);token(c,0x0021,0x6F,0x06003C24)
 if c[0x0026]!=0x2A:raise E("ret")
 token(cc,0x0000,0x28,0x06005171)
 print("PROVE_SAVE_DATA_STORY_WORK_GETTER: PASS")
if __name__=="__main__":main()
