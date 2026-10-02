#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS=[
 (0x060052D2,0x00325741,"72cc88b5b683b160abc8e7954fbaf73bc594488ba0cf95ae7d65958b1e21730c"),
 (0x060052D3,0x00325748,"72cc88b5b683b160abc8e7954fbaf73bc594488ba0cf95ae7d65958b1e21730c"),
 (0x060052ED,0x00325E63,"72cc88b5b683b160abc8e7954fbaf73bc594488ba0cf95ae7d65958b1e21730c")
]
BODY=bytes.fromhex("73c503000a7a")
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
 if b&3!=2:raise E("expected tiny")
 n=b>>2
 return pe[o+1:o+1+n]
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 for tok,rva,sha in METHODS:
  c=body(pe,ss,rva)
  if c!=BODY or hashlib.sha256(c).hexdigest()!=sha:raise E(hex(tok)+" body")
 tctor=struct.pack("<I",0x0A0003C5)
 if BODY[:5]!=b"\x73"+tctor or BODY[5]!=0x7A:raise E("shared newobj/throw")
 prefixes=[b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"]
 for tok,_,_ in METHODS:
  t=struct.pack("<I",tok)
  for p in prefixes:
   if pe.find(p+t)>=0:raise E("direct reference "+hex(tok))
 print("PROVE_U_AUDIO_NOT_IMPLEMENTED_STUBS: PASS")
if __name__=="__main__":main()
