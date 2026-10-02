#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325E0C
SIZE=18
CODE_SHA="d5e285b4ad9285059afee97848d43a163c62ba65523f54379a5d5b6c8248a513"
BODY=bytes.fromhex("027be987000439060000000228e65200062a")
TOKEN=0x060052EA
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
 c=body(pe,sections(pe),RVA)
 if c!=BODY or len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if c[0]!=0x02 or c[1]!=0x7B or struct.unpack_from("<I",c,2)[0]!=0x040087E9:raise E("State")
 if c[6]!=0x39 or 6+5+struct.unpack_from("<i",c,7)[0]!=0x11:raise E("zero branch")
 if c[0x0B]!=0x02 or c[0x0C]!=0x28 or struct.unpack_from("<I",c,0x0D)[0]!=0x060052E6:raise E("SongEnd")
 if c[0x11]!=0x2A:raise E("ret")
 t=struct.pack("<I",TOKEN)
 for pre in [b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"]:
  if pe.find(pre+t)>=0:raise E("inbound direct ref")
 print("PROVE_U_AUDIO_STOP: PASS")
if __name__=="__main__":main()
