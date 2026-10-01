#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325E6A
SIZE=13
CODE_SHA="124f59a872afec501c29839a33e627e58a6c5339d59456ad7f66f6b7323e237d"
PARENT_RVA=0x00325714
PARENT_SHA="5524703abb8912537cca2bf60cf25fdcde63df8bcc2ea51a0db76d5dc8e858c4"
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
 ss=sections(pe);c=body(pe,ss,RVA);p=body(pe,ss,PARENT_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(p).hexdigest()!=PARENT_SHA:raise E("parent")
 if c[0]!=0x02:raise E("this")
 tok(c,0x0001,0x7B,0x040087E7,"_sendPlaybackState")
 if c[0x0006]!=0x03:raise E("c")
 tok(c,0x0007,0x6F,0x0A000FC4,"Action Invoke")
 if c[0x000C]!=0x2A:raise E("ret")
 if p[0x003F:0x0041]!=bytes([0xFE,0x06]) or struct.unpack_from("<I",p,0x0041)[0]!=0x060052EE:raise E("FACT-0138 ldftn")
 print("PROVE_U_AUDIO_GET_U_AUDIO_CALLBACK: PASS")
if __name__=="__main__":main()
