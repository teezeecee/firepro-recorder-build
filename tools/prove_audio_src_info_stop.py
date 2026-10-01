#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00323806
SIZE=43
CODE_SHA="6367793f54b558ae8629023c6246cc6a97b366e8e4cf5761be3343d3cafcb76a"
CALLER_RVA=0x003229E0
CALLER_SHA="5ba3bf95e0ffa2db0c9766a6254c9016dab003ed26d580ec573effd8e2966b51"
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
 if c[0]!=0x02:raise E("this source #1")
 tok(c,0x0001,0x7B,0x0400874C,"sRefAudio #1")
 if c[0x0006]!=0x14:raise E("null")
 tok(c,0x0007,0x28,0x0A00000F,"Object.op_Inequality")
 br(c,0x000C,0x39,0x001C,"null branch")
 if c[0x0011]!=0x02:raise E("this source #2")
 tok(c,0x0012,0x7B,0x0400874C,"sRefAudio #2")
 tok(c,0x0017,0x6F,0x0A00079F,"AudioSource.Stop")
 if c[0x001C:0x001E]!=bytes([0x02,0x16]):raise E("fadeOutFrm args")
 tok(c,0x001E,0x7D,0x0400874E,"fadeOutFrm")
 if c[0x0023:0x0025]!=bytes([0x02,0x16]):raise E("fadeOutCnt args")
 tok(c,0x0025,0x7D,0x0400874D,"fadeOutCnt")
 if c[0x002A]!=0x2A:raise E("ret")
 tok(cc,0x0009,0x6F,0x060052C4,"FACT-0123 caller")
 print("PROVE_AUDIO_SRC_INFO_STOP: PASS")
if __name__=="__main__":main()
