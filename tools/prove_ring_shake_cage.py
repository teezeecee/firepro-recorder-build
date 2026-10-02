#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0030E2F0;SIZE=8;CODE_SHA="dc90ddc959a5183de014264fdbd38c6d4f4b92fa95ac83949817fbbe1adb79b3"
FACT0015_RVA=0x002DB718;FACT0015_SHA="ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"header":1,"code":pe[o+1:o+1+(b>>2)]}
 raise E("expected tiny header")
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=method(pe,ss,RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if c[0:2]!=bytes([0x02,0x16]):raise E("this/raw0")
 tok(c,0x0002,0x7D,0x0400636F,"ShakeCageAnmCnt")
 if c[0x0007]!=0x2A:raise E("ret")
 # FACT-0015 is fat-header; extract inline
 for va,sz,rp in ss:
  if va<=FACT0015_RVA<va+sz:o=rp+FACT0015_RVA-va;break
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0];p=pe[o+h:o+h+n]
 if hashlib.sha256(p).hexdigest()!=FACT0015_SHA:raise E("FACT0015")
 tok(p,0x012A,0x6F,0x0600510A,"FACT0015 inbound")
 print("PROVE_RING_SHAKE_CAGE: PASS")
if __name__=="__main__":main()
