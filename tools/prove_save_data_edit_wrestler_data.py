#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003166EC
SIZE=47
CODE_SHA="fb1d5036d90b5023700c012f02b2775cd7c763c0a131ba63904e8f7a6bc56998"
CALLER_RVA=0x002A95D8
CALLER_SHA="57fe61387e5df262b4c752819960c309b4a48a1a2299a231f8f5199a6e69eeb3"
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
 if b&3==2:
  return {"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];cc=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["max_stack"]!=2 or m["local_sig"]!=0x1100003A:raise E("header")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0x0000:0x0002]!=bytes([0x02,0x03]):raise E("this/wid")
 tok(c,0x0002,0x28,0x060051B5,"GetEditWrestlerIdx")
 if c[0x0007:0x000A]!=bytes([0x0A,0x06,0x16]):raise E("idx local / zero")
 br(c,0x000A,0x3F,0x0020,"idx < 0")
 if c[0x000F:0x0011]!=bytes([0x06,0x02]):raise E("idx/list receiver")
 tok(c,0x0011,0x7B,0x040064F5,"editWrestlerData #1")
 tok(c,0x0016,0x6F,0x0A0007A4,"List get_Count")
 br(c,0x001B,0x3F,0x0022,"idx < Count")
 if c[0x0020:0x0022]!=bytes([0x14,0x2A]):raise E("null return")
 if c[0x0022]!=0x02:raise E("list receiver #2")
 tok(c,0x0023,0x7B,0x040064F5,"editWrestlerData #2")
 if c[0x0028]!=0x06:raise E("idx item")
 tok(c,0x0029,0x6F,0x0A0007A3,"List get_Item")
 if c[0x002E]!=0x2A:raise E("item return")
 tok(cc,0x0059,0x6F,0x060051B9,"FACT-0096 caller")
 print("PROVE_SAVE_DATA_EDIT_WRESTLER_DATA: PASS")
if __name__=="__main__":main()
