#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS=[
 (0x003256A9,0x040087F0,"3b48fea46caaa08bb28913761369616052fa428e05ac01794405c97037077524"),
 (0x00325874,0x040087E9,"de9e085e87cf7a30cee821d754f612492037d0724898532d5e64b3e83190f35b"),
 (0x00325885,0x040087E6,"500993c92324149c54aae4e0fdb7fd72b686e983c05b0219ff6e1931181031c9")]
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3!=2:raise E("tiny")
 n=b>>2
 return pe[o+1:o+1+n]
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 for rva,field,sha in METHODS:
  c=body(pe,ss,rva)
  if len(c)!=7 or hashlib.sha256(c).hexdigest()!=sha:raise E(hex(rva)+" body")
  if c[0]!=0x02 or c[1]!=0x7B or struct.unpack_from("<I",c,2)[0]!=field or c[6]!=0x2A:raise E(hex(rva)+" getter")
 print("PROVE_U_AUDIO_FIELD_GETTERS: PASS")
if __name__=="__main__":main()
