#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00323320
SIZE=8
CODE_SHA="8b924ec5650c79c888696f801976f2f99b92a71ba35fb44d7fcabce6d6e4c799"
ROW_HEX="203332000000810018620a006a550000483d"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def locate(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise E("rva")
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);o=locate(ss,RVA);fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4
 if (fs&0x0FFF)!=0x0013 or h!=12:raise E("header flags")
 if struct.unpack_from("<H",pe,o+2)[0]!=1:raise E("maxstack")
 if struct.unpack_from("<I",pe,o+4)[0]!=SIZE:raise E("size")
 if struct.unpack_from("<I",pe,o+8)[0]!=0x11001214:raise E("localsig token")
 c=pe[o+h:o+h+SIZE]
 if hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if c[0]!=0x73 or struct.unpack_from("<I",c,1)[0]!=0x0600750E:raise E("iterator ctor")
 if c[5:]!=bytes([0x0A,0x06,0x2A]):raise E("stloc/ldloc/ret")
 print("PROVE_MENU_SOUND_MY_MUSIC_PLAY_CO_FACTORY: PASS")
if __name__=="__main__":main()
