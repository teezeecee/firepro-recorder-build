#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00316558
SIZE=68
CODE_SHA="d3a61b6659b558132c7269733dda2c9925958fc65d6a5925f84474e04d42969d"
CALLER_RVA=0x003166EC
CALLER_SHA="fb1d5036d90b5023700c012f02b2775cd7c763c0a131ba63904e8f7a6bc56998"
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
 if b&3==2:return {"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];cc=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["max_stack"]!=2 or m["local_sig"]!=0x1100003A:raise E("header")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0x0000]!=0x03:raise E("wid")
 i4(c,0x0001,10000,"raw10000")
 br(c,0x0006,0x3C,0x000D,"wid >= 10000")
 if c[0x000B:0x000D]!=bytes([0x15,0x2A]):raise E("early -1")
 if c[0x000D:0x000F]!=bytes([0x16,0x0A]):raise E("index zero")
 br(c,0x000F,0x38,0x0031,"loop test jump")
 if c[0x0014]!=0x02:raise E("list receiver")
 tok(c,0x0015,0x7B,0x040064F5,"editWrestlerData #1")
 if c[0x001A]!=0x06:raise E("index item")
 tok(c,0x001B,0x6F,0x0A0007A3,"List get_Item")
 tok(c,0x0020,0x7B,0x040010BD,"editWrestlerID")
 if c[0x0025]!=0x03:raise E("wid compare")
 br(c,0x0026,0x40,0x002D,"not equal")
 if c[0x002B:0x002D]!=bytes([0x06,0x2A]):raise E("matching index return")
 if c[0x002D:0x0031]!=bytes([0x06,0x17,0x58,0x0A]):raise E("index increment")
 if c[0x0031:0x0033]!=bytes([0x06,0x02]):raise E("loop compare args")
 tok(c,0x0033,0x7B,0x040064F5,"editWrestlerData #2")
 tok(c,0x0038,0x6F,0x0A0007A4,"List get_Count")
 br(c,0x003D,0x3F,0x0014,"index < Count")
 if c[0x0042:0x0044]!=bytes([0x15,0x2A]):raise E("final -1")
 tok(cc,0x0002,0x28,0x060051B5,"FACT-0102 caller")
 print("PROVE_SAVE_DATA_EDIT_WRESTLER_INDEX: PASS")
if __name__=="__main__":main()
