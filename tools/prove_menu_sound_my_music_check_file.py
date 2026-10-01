#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00323103
SIZE=43
CODE_SHA="662652aabb116c9ffa4f8e994a1ad55ed75cb54c40114569e6a0b8be4c140978"
CALLER_RVA=0x00323130
CALLER_SHA="e84b8a91478acffadf8ee5f39f17855e421d0cf1b4d482f97dfbb53700440a5a"
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
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0]!=0x03:raise E("fname #1")
 tok(c,0x0001,0x7E,0x0A000025,"String.Empty")
 tok(c,0x0006,0x28,0x0A00002F,"String.op_Equality")
 br(c,0x000B,0x39,0x0012,"non-empty branch")
 if c[0x0010:0x0012]!=bytes([0x16,0x2A]):raise E("empty false")
 tok(c,0x0012,0x7E,0x04003903,"Root_DirectotyPath")
 if c[0x0017]!=0x03:raise E("fname #2")
 tok(c,0x0018,0x28,0x0A000012,"String.Concat")
 tok(c,0x001D,0x28,0x0A000216,"File.Exists")
 br(c,0x0022,0x3A,0x0029,"exists true")
 if c[0x0027:0x0029]!=bytes([0x16,0x2A]):raise E("exists false")
 if c[0x0029:0x002B]!=bytes([0x17,0x2A]):raise E("exists true return")
 for off in (0x0026,0x0065,0x011C):tok(cc,off,0x28,0x060052B7,"FACT-0133 caller")
 print("PROVE_MENU_SOUND_MY_MUSIC_CHECK_FILE: PASS")
if __name__=="__main__":main()
