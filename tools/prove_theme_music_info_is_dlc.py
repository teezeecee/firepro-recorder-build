#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006CAE4
SIZE=36
CODE_SHA="493b5cdc804f432200f9198f85dbd365d62854ee6f944047f0cd690002c2f3cd"
CALLER_RVA=0x00322268
CALLER_SHA="2e0905ada32d6f97c3a3ac37f28bb0722b6084a109618070cf1dfc1ea1fb4733"
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
 if b&3==2:return {"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
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
 if m["max_stack"]!=2 or m["local_sig"]!=0x1100003A:raise E("header")
 if c[0x0000:0x0002]!=bytes([0x16,0x0A]):raise E("index init")
 br(c,0x0002,0x38,0x001A,"initial condition branch")
 if c[0x0007]!=0x02:raise E("this")
 tok(c,0x0008,0x7B,0x04000FB8,"ThemeMusicInfo.dlc")
 if c[0x000D:0x000F]!=bytes([0x06,0x91]):raise E("dlc[index]")
 br(c,0x000F,0x39,0x0016,"zero element branch")
 if c[0x0014:0x0016]!=bytes([0x17,0x2A]):raise E("true return")
 if c[0x0016:0x001A]!=bytes([0x06,0x17,0x58,0x0A]):raise E("index increment")
 if c[0x001A:0x001D]!=bytes([0x06,0x1F,0x10]):raise E("index/raw16")
 br(c,0x001D,0x3F,0x0007,"signed index < 16")
 if c[0x0022:0x0024]!=bytes([0x16,0x2A]):raise E("false return")
 tok(cc,0x0059,0x6F,0x06001192,"FACT-0111 IsDLC #1")
 tok(cc,0x00B8,0x6F,0x06001192,"FACT-0111 IsDLC #2")
 print("PROVE_THEME_MUSIC_INFO_IS_DLC: PASS")
if __name__=="__main__":main()
