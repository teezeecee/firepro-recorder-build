#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x001AE857
SIZE=44
CODE_SHA="d390c42b59fdb5e492f5477ea4ebd30bb039048a3feebf4e7b82d7f2dd35a59a"
CALLER_RVA=0x00299808
CALLER_SHA="c64099c6e74a32eaa9dcc01c14768a9687140d2da506f443bd11da9449a5bb58"
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
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0x0000:0x0003]!=bytes([0x02,0x1F,0x21]):raise E("raw33 compare")
 br(c,0x0003,0x3B,0x0015,"raw33 branch")
 if c[0x0008:0x000B]!=bytes([0x02,0x1F,0x22]):raise E("raw34 compare")
 br(c,0x000B,0x3B,0x0020,"raw34 branch")
 br(c,0x0010,0x38,0x002B,"default return")
 if c[0x0015]!=0x03:raise E("fname #1")
 tok(c,0x0016,0x80,0x04008705,"MyMusic_SelectFile_Admission")
 br(c,0x001B,0x38,0x002B,"raw33 return")
 if c[0x0020]!=0x03:raise E("fname #2")
 tok(c,0x0021,0x80,0x04008704,"MyMusic_SelectFile_Match")
 br(c,0x0026,0x38,0x002B,"raw34 return")
 if c[0x002B]!=0x2A:raise E("ret")
 if cc[0x00BD:0x00BF]!=bytes([0x1F,0x21]):raise E("FACT-0108 raw33 #1")
 tok(cc,0x00C4,0x28,0x06002C23,"FACT-0108 Set #1")
 if cc[0x00CE:0x00D0]!=bytes([0x1F,0x21]):raise E("FACT-0108 raw33 #2")
 tok(cc,0x00D7,0x28,0x06002C23,"FACT-0108 Set #2")
 print("PROVE_MYMUSIC_SET: PASS")
if __name__=="__main__":main()
