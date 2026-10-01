#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00322430
SIZE=125
CODE_SHA="3d1bd7f767849f9b77dd562c223725e3f1614d823843c55b71a12d7b15303c18"
CALLER_RVA=0x002A96A8
CALLER_SHA="ce8a2a91a564c9f28928b39c7d444dfe0758d3b771b7a142125e5bac4daaa2b5"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];cc=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if m["flags"]!=0x0013 or m["max_stack"]!=5 or m["local_sig"]!=0x11001204:raise E("header")
 if c[0]!=0x03:raise E("bAsync")
 br(c,0x0001,0x39,0x0041,"sync branch")
 if c[0x0006]!=0x16:raise E("progress false async")
 tok(c,0x0007,0x80,0x04008703,"progress async")
 if c[0x000C:0x000E]!=bytes([0x1F,0x0F]):raise E("keep raw15 async")
 tok(c,0x000E,0x80,0x04008702,"keep async")
 tok(c,0x0013,0x7E,0x0A000025,"String.Empty async")
 tok(c,0x0018,0x80,0x04008705,"admission async")
 tok(c,0x001D,0x28,0x0600527C,"FACT-0112 get_instance")
 tok(c,0x0022,0x72,0x7008EAFC,"resource prefix async")
 if c[0x0027]!=0x02:raise E("fn async")
 tok(c,0x0028,0x28,0x0A000012,"String.Concat async")
 if c[0x002D:0x002F]!=bytes([0x1F,0x21]):raise E("raw33 async")
 if c[0x002F:0x0031]!=bytes([0x04,0x14]):raise E("bStart/null")
 tok(c,0x0031,0x28,0x06005294,"FACT-0115 CoChange")
 tok(c,0x0036,0x6F,0x0A00035A,"StartCoroutine")
 if c[0x003B]!=0x26:raise E("pop coroutine")
 br(c,0x003C,0x38,0x007C,"async return")
 tok(c,0x0041,0x72,0x7008EAFC,"resource prefix sync")
 if c[0x0046]!=0x02:raise E("fn sync")
 tok(c,0x0047,0x28,0x0A000012,"String.Concat sync")
 tok(c,0x004C,0x28,0x0A0006DA,"Resources.Load")
 tok(c,0x0051,0x74,0x01000012,"AudioClip cast")
 if c[0x0056]!=0x0A:raise E("stloc0")
 tok(c,0x0057,0x7E,0x040086F4,"audioClipInfo")
 if c[0x005C:0x005E]!=bytes([0x1F,0x21]) or c[0x005E]!=0x9A:raise E("audioClipInfo[33]")
 if c[0x005F]!=0x06:raise E("ldloc0")
 tok(c,0x0060,0x6F,0x060052C2,"FACT-0113 AudioClipInfo.Set")
 if c[0x0065]!=0x16:raise E("progress false sync")
 tok(c,0x0066,0x80,0x04008703,"progress sync")
 if c[0x006B:0x006D]!=bytes([0x1F,0x0F]):raise E("keep raw15 sync")
 tok(c,0x006D,0x80,0x04008702,"keep sync")
 tok(c,0x0072,0x7E,0x0A000025,"String.Empty sync")
 tok(c,0x0077,0x80,0x04008705,"admission sync")
 if c[0x007C]!=0x2A:raise E("ret")
 tok(cc,0x00F0,0x28,0x06005298,"FACT-0122 caller")
 print("PROVE_MENU_SOUND_CHANGE_BGM_THEME_STRING: PASS")
if __name__=="__main__":main()
