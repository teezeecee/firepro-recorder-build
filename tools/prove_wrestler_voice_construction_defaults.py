#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M=[
 (0x0006F013,26,"6836ea693beefcbacf0cca451f7be338d0113f53f4ce8b3710d8cf6b5039039a"),
 (0x0006F030,65,"941c4078e31edb844e0a3e59cb5ae28a6dedf8e86b01896fbaacf71c0a699a60"),
 (0x0006F100,29,"d73d650906909f5df68b9d1210095d7763ad6ca99a890b3fce2dd6238b6918f7")
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
 bodies=[]
 for rva,n,sha in M:
  c=body(pe,ss,rva)
  if len(c)!=n or hashlib.sha256(c).hexdigest()!=sha:raise E("body "+hex(rva))
  bodies.append(c)
 a1,i1,mgr=bodies
 if a1[0:2]!=bytes([0x02,0x18]):raise E("Attr string[2] args")
 tok(a1,0x0002,0x8D,0x010000BF,"Attr String newarr")
 tok(a1,0x0007,0x7D,0x040011DB,"Attr description")
 if a1[0x000C:0x000E]!=bytes([0x02,0x15]):raise E("Attr cheer -1 args")
 tok(a1,0x000E,0x7D,0x040011DC,"Attr cheerVoice")
 if a1[0x0013]!=0x02:raise E("Attr this base")
 tok(a1,0x0014,0x28,0x0A0000EF,"Object ctor")
 if a1[0x0019]!=0x2A:raise E("Attr ret")
 if i1[0:3]!=bytes([0x02,0x1F,0x10]):raise E("Info bool[16] args")
 tok(i1,0x0003,0x8D,0x010000C8,"Info Boolean newarr")
 tok(i1,0x0008,0x7D,0x040011DE,"Info dlc")
 if i1[0x000D]!=0x02:raise E("Info parent this")
 tok(i1,0x000E,0x7E,0x0A000025,"String.Empty parent")
 tok(i1,0x0013,0x7D,0x040011DF,"parentFolder")
 if i1[0x0018]!=0x02:raise E("Info prefix this")
 tok(i1,0x0019,0x7E,0x0A000025,"String.Empty prefix")
 tok(i1,0x001E,0x7D,0x040011E0,"fileNamePrefix")
 if i1[0x0023:0x0025]!=bytes([0x02,0x18]):raise E("Info name[2] args")
 tok(i1,0x0025,0x8D,0x010000BF,"Info String newarr")
 tok(i1,0x002A,0x7D,0x040011E1,"Info name")
 if i1[0x002F]!=0x02:raise E("Info attr this")
 tok(i1,0x0030,0x73,0x0A000786,"List Attr ctor")
 tok(i1,0x0035,0x7D,0x040011E3,"Info attr")
 if i1[0x003A]!=0x02:raise E("Info base this")
 tok(i1,0x003B,0x28,0x0A0000EF,"Info Object ctor")
 if i1[0x0040]!=0x2A:raise E("Info ret")
 if mgr[0]!=0x02:raise E("Manager list this")
 tok(mgr,0x0001,0x73,0x0A000791,"List Info ctor")
 tok(mgr,0x0006,0x7D,0x040011E7,"manager list field")
 if mgr[0x000B]!=0x02:raise E("Manager attr this")
 tok(mgr,0x000C,0x73,0x060011E1,"Manager Attr ctor")
 tok(mgr,0x0011,0x7D,0x040011E8,"unknown attr field")
 if mgr[0x0016]!=0x02:raise E("Manager base this")
 tok(mgr,0x0017,0x28,0x0A00000E,"MonoBehaviour ctor")
 if mgr[0x001C]!=0x2A:raise E("Manager ret")
 print("PROVE_WRESTLER_VOICE_CONSTRUCTION_DEFAULTS: PASS")
if __name__=="__main__":main()
