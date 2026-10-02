#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS={
0x060052CF:(0x003256B1,"2dd474a11591e000678f479f2d90becf09ceca30baa460e3ec548152f79511de",bytes.fromhex("027be3870004390c000000027be3870004036fb00f000a02037df08700042a")),
0x060052DD:(0x00325835,"bdcad7e05493de6d828b070a1ebebada023b8623afedb806639dede39f46a105",bytes.fromhex("027be3870004390c000000027be38700046fbe0f000a2a0228ce5200062a")),
0x060052DE:(0x00325854,"c77479fb0ce8779178f36cdfedf65a4a1a72293210533a34202937657ad3304b",bytes.fromhex("027be3870004390c000000027be3870004036fb00f000a020328cf5200062a"))
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
 ss=sections(pe);codes={}
 for tok,(rva,sha,expected) in METHODS.items():
  c=body(pe,ss,rva);codes[tok]=c
  if c!=expected or hashlib.sha256(c).hexdigest()!=sha:raise E("body "+hex(tok))
 # all three gate _uAudio at IL0x0001 and null branch to IL0x0017
 for tok,c in codes.items():
  if c[0]!=0x02 or c[1]!=0x7B or struct.unpack_from("<I",c,2)[0]!=0x040087E3:raise E("backend gate "+hex(tok))
  if c[6]!=0x39 or 6+5+struct.unpack_from("<i",c,7)[0]!=0x17:raise E("branch "+hex(tok))
 if codes[0x060052CF][0x12]!=0x6F or struct.unpack_from("<I",codes[0x060052CF],0x13)[0]!=0x0A000FB0:raise E("offset backend set")
 if codes[0x060052CF][0x19]!=0x7D or struct.unpack_from("<I",codes[0x060052CF],0x1A)[0]!=0x040087F0:raise E("offset store")
 if codes[0x060052DD][0x11]!=0x6F or struct.unpack_from("<I",codes[0x060052DD],0x12)[0]!=0x0A000FBE:raise E("backend get")
 if codes[0x060052DD][0x18]!=0x28 or struct.unpack_from("<I",codes[0x060052DD],0x19)[0]!=0x060052CE:raise E("offset getter")
 if codes[0x060052DE][0x12]!=0x6F or struct.unpack_from("<I",codes[0x060052DE],0x13)[0]!=0x0A000FB0:raise E("backend set")
 if codes[0x060052DE][0x19]!=0x28 or struct.unpack_from("<I",codes[0x060052DE],0x1A)[0]!=0x060052CF:raise E("offset setter")
 # direct MethodDef token scan: exactly one direct call to CF, none to DD/DE
 for tok in [0x060052DD,0x060052DE]:
  t=struct.pack("<I",tok)
  for pre in [b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"]:
   if pe.find(pre+t)>=0:raise E("unexpected inbound "+hex(tok))
 if pe.count(b"\x28"+struct.pack("<I",0x060052CF))!=1:raise E("CF inbound count")
 print("PROVE_U_AUDIO_VOLUME_ROUTING: PASS")
if __name__=="__main__":main()
