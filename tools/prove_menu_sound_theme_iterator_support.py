#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS=[
 (0x00324D2C,7,"010e7d2894e129945449584a26a5fd0e99e10c9f6dbcd65faffa03ff8c244d73","current",0x0400C242,None,None),
 (0x00324D34,7,"010e7d2894e129945449584a26a5fd0e99e10c9f6dbcd65faffa03ff8c244d73","current",0x0400C242,None,None),
 (0x00324D3C,15,"e86626c33062562b8370a39954a1cd69a0cf16f25abd8ed69745e512cd39449d","dispose",None,0x0400C243,0x0400C244),
 (0x00324D4C,6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49","reset",None,None,None),
 (0x00324E60,7,"a9d9e52dc49e2933d096b9672481b9e8d64ed398998606a4b5639a3924f9553f","current",0x0400C24A,None,None),
 (0x00324E68,7,"a9d9e52dc49e2933d096b9672481b9e8d64ed398998606a4b5639a3924f9553f","current",0x0400C24A,None,None),
 (0x00324E70,15,"901ca17e2ae4c9e392c1d7c503318763a7e507f7ad3595d277e4495bac74000a","dispose",None,0x0400C24B,0x0400C24C),
 (0x00324E80,6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49","reset",None,None,None)
]
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
 ss=sections(pe)
 for rva,size,sha,kind,current,disposing,pc in METHODS:
  c=body(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E("body")
  if kind=="current":
   if c[0]!=0x02:raise E("current this")
   tok(c,0x0001,0x7B,current,"current field")
   if c[0x0006]!=0x2A:raise E("current ret")
  elif kind=="dispose":
   if c[0:2]!=bytes([0x02,0x17]):raise E("disposing true")
   tok(c,0x0002,0x7D,disposing,"disposing field")
   if c[0x0007:0x0009]!=bytes([0x02,0x15]):raise E("pc -1")
   tok(c,0x0009,0x7D,pc,"pc field")
   if c[0x000E]!=0x2A:raise E("dispose ret")
  else:
   tok(c,0x0000,0x73,0x0A0000EE,"NotSupportedException ctor")
   if c[0x0005]!=0x7A:raise E("throw")
 print("PROVE_MENU_SOUND_THEME_ITERATOR_SUPPORT: PASS")
if __name__=="__main__":main()
