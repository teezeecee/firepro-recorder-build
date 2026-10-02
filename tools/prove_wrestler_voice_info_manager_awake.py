#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006F11E
SIZE=61
CODE_SHA="bcee56df40b0e166d956e871a4b165a2e11eed714129aff4e22590ffbe441aae"
TOKEN=0x060011E6
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
 if b&3!=2:raise E("expected tiny header")
 return pe[o+1:o+1+(b>>2)]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if c[0]!=0x02:raise E("inst this")
 tok(c,0x0001,0x80,0x040011E6,"inst stsfld")
 if c[0x0006]!=0x02:raise E("fallback this #1")
 tok(c,0x0007,0x7B,0x040011E8,"fallback #1")
 tok(c,0x000C,0x7B,0x040011DB,"description #1")
 if c[0x0011]!=0x16:raise E("index 0")
 tok(c,0x0012,0x72,0x70007D32,"Unknown #1")
 if c[0x0017]!=0xA2:raise E("stelem.ref #1")
 if c[0x0018]!=0x02:raise E("fallback this #2")
 tok(c,0x0019,0x7B,0x040011E8,"fallback #2")
 tok(c,0x001E,0x7B,0x040011DB,"description #2")
 if c[0x0023]!=0x17:raise E("index 1")
 tok(c,0x0024,0x72,0x70007D32,"Unknown #2")
 if c[0x0029]!=0xA2:raise E("stelem.ref #2")
 if c[0x002A]!=0x02:raise E("fallback cheer this")
 tok(c,0x002B,0x7B,0x040011E8,"fallback cheer")
 if c[0x0030]!=0x15:raise E("raw -1")
 tok(c,0x0031,0x7D,0x040011DC,"cheerVoice")
 if c[0x0036]!=0x02:raise E("Parse this")
 tok(c,0x0037,0x28,0x060011EA,"Parse")
 if c[0x003C]!=0x2A:raise E("ret")
 t=struct.pack("<I",TOKEN)
 for pre in [b"\x28",b"\x6f",b"\x73",b"\xfe\x06",b"\xfe\x07"]:
  if pe.find(pre+t)>=0:raise E("direct Awake ref")
 print("PROVE_WRESTLER_VOICE_INFO_MANAGER_AWAKE: PASS")
if __name__=="__main__":main()
