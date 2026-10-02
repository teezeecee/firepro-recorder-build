#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
EXPECTED=[
(0x00325600,7,"b8e8332bb9870be9197c321e9365333a1cc8b38ee55cb82ca1e204f0d455de8b"),
(0x00325608,7,"b8e8332bb9870be9197c321e9365333a1cc8b38ee55cb82ca1e204f0d455de8b"),
(0x00325610,15,"02a2aa96e1a791fff16cf503f1e698d0ecfbf56270e49599e8042faf50fd0a18"),
(0x00325620,6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49")
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
 ss=sections(pe);cs=[]
 for rva,size,sha in EXPECTED:
  c=body(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E("body "+hex(rva))
  cs.append(c)
 for idx,c in enumerate(cs[:2]):
  if c[0]!=0x02:raise E("get_Current this "+str(idx))
  tok(c,1,0x7B,0x0400C26D,"get_Current $current")
  if c[6]!=0x2A:raise E("get_Current ret")
 c=cs[2]
 if c[0:2]!=bytes([0x02,0x17]):raise E("Dispose disposing args")
 tok(c,2,0x7D,0x0400C26E,"Dispose $disposing")
 if c[7:9]!=bytes([0x02,0x15]):raise E("Dispose PC args")
 tok(c,9,0x7D,0x0400C26F,"Dispose $PC")
 if c[14]!=0x2A:raise E("Dispose ret")
 c=cs[3]
 if c[0]!=0x73 or struct.unpack_from("<I",c,1)[0]!=0x0A0000EE or c[5]!=0x7A:raise E("Reset")
 print("PROVE_MENU_SOUND_MY_MUSIC_PLAY_CO_SUPPORT: PASS")
if __name__=="__main__":main()
