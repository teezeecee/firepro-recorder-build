#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
EXPECTED={
0x060052D5:(0x00325758,"c90322aba94a9bdb71409ad82330912a9b3749566383217b56951c45c2a42293",bytes.fromhex("027be3870004390c000000027be38700046fb70f000a2a7e2500000a2a")),
0x060052DA:(0x003257FC,"c2d0be581347b6907ae28115746372eaad0f60669f9234113bc3e38abfbd3994",bytes.fromhex("027be3870004390c000000027be38700046fbc0f000a2a7ebd0f000a2a"))
}
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3!=2:raise E("tiny")
 return pe[o+1:o+1+(b>>2)]
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 for tok,(rva,sha,expected) in EXPECTED.items():
  c=body(pe,ss,rva)
  if c!=expected or len(c)!=29 or hashlib.sha256(c).hexdigest()!=sha:raise E("body "+hex(tok))
  if c[0]!=0x02 or c[1]!=0x7B or struct.unpack_from("<I",c,2)[0]!=0x040087E3:raise E("backend gate "+hex(tok))
  if c[6]!=0x39 or 6+5+struct.unpack_from("<i",c,7)[0]!=0x17:raise E("fallback branch "+hex(tok))
  if c[0x0B]!=0x02 or c[0x0C]!=0x7B or struct.unpack_from("<I",c,0x0D)[0]!=0x040087E3:raise E("backend load "+hex(tok))
  if c[0x16]!=0x2A or c[0x1C]!=0x2A:raise E("returns "+hex(tok))
 for tok in EXPECTED:
  t=struct.pack("<I",tok)
  for pre in [b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"]:
   if pe.find(pre+t)>=0:raise E("inbound ref "+hex(tok))
 print("PROVE_U_AUDIO_BACKEND_FALLBACK_GETTERS: PASS")
if __name__=="__main__":main()
