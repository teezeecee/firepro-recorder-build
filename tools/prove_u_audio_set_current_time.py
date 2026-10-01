#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003257A0
SIZE=24
CODE_SHA="c09298a196302aaeb2cd6734a8b2297724c09221a9602d15e85257482f52199c"
CALLER_RVA=0x00325A80
CALLER_SHA="25cfa99ab6e97f650b4e517fa419b12acb018df2aab2933a87b40953a7084a26"
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
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0]!=0x02:raise E("this gate")
 tok(c,0x0001,0x7B,0x040087E3,"_uAudio gate")
 br(c,0x0006,0x39,0x0017,"null return")
 if c[0x000B]!=0x02:raise E("this call")
 tok(c,0x000C,0x7B,0x040087E3,"_uAudio call")
 if c[0x0011]!=0x03:raise E("value")
 tok(c,0x0012,0x6F,0x0A000FB9,"backend set_CurrentTime")
 if c[0x0017]!=0x2A:raise E("ret")
 for off in (0x018D,0x019F):tok(cc,off,0x28,0x060052D7,"FACT-0140 caller")
 print("PROVE_U_AUDIO_SET_CURRENT_TIME: PASS")
if __name__=="__main__":main()
