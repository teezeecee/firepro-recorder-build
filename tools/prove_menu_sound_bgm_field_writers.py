#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
EXPECTED={
0x003229D0:(bytes.fromhex("1780038700040280028700042a"),"e4b40d03b2d5fa1894f4bcdd314fe8860105a11edb0df6b7f260115e6f51abf9"),
0x00322A27:(bytes.fromhex("0280f68600040280f78600042a"),"26438a04e2990fa90e8ac47da1d35ac4bc09608c539517d58e490194a1731a18")
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
 if b&3!=2:raise E("expected tiny")
 return pe[o+1:o+1+(b>>2)]
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 for rva,(exp,sha) in EXPECTED.items():
  c=body(pe,ss,rva)
  if c!=exp or hashlib.sha256(c).hexdigest()!=sha:raise E(hex(rva))
 a=body(pe,ss,0x003229D0)
 if a[0]!=0x17 or a[1]!=0x80 or struct.unpack_from("<I",a,2)[0]!=0x04008703:raise E("continue flag")
 if a[6]!=0x02 or a[7]!=0x80 or struct.unpack_from("<I",a,8)[0]!=0x04008702 or a[12]!=0x2A:raise E("keep BGM writer")
 b=body(pe,ss,0x00322A27)
 if b[0]!=0x02 or b[1]!=0x80 or struct.unpack_from("<I",b,2)[0]!=0x040086F6:raise E("fade cnt")
 if b[6]!=0x02 or b[7]!=0x80 or struct.unpack_from("<I",b,8)[0]!=0x040086F7 or b[12]!=0x2A:raise E("fade frm")
 print("PROVE_MENU_SOUND_BGM_FIELD_WRITERS: PASS")
if __name__=="__main__":main()
