#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00304B6C
SIZE=25
CODE_SHA="32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8"
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
 if c[0x0000:0x0002]!=bytes([0x03,0x16]):raise E("idx/raw0")
 br(c,0x0002,0x3F,0x000E,"idx < 0")
 if c[0x0007:0x0009]!=bytes([0x03,0x1E]):raise E("idx/raw8")
 br(c,0x0009,0x3F,0x0010,"idx < 8")
 if c[0x000E:0x0010]!=bytes([0x14,0x2A]):raise E("null return")
 if c[0x0010]!=0x02:raise E("this")
 tok(c,0x0011,0x7B,0x040061FF,"PlayerMan.PlObj")
 if c[0x0016:0x0019]!=bytes([0x03,0x9A,0x2A]):raise E("PlObj[idx] return")
 tok(cc,0x0016,0x6F,0x06005065,"FACT-0108 caller")
 print("PROVE_PLAYER_MAN_GET_PL_OBJ: PASS")
if __name__=="__main__":main()
