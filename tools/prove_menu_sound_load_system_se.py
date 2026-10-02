#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
LOAD_RVA=0x003219D0
LOAD_SHA="a3013c457438736875e2b086380b1531557597d34461483561823549e742c67b"
SET_RVA=0x003237F5
SET_SHA="5c1fa2fbc6a929b6fffb5ebb0e04fae4d1fa8b86b4d1984529906b46d8824dd0"
PARENT_RVA=0x003217EC
PARENT_SHA="11a01435a5eb88584d4a811a33bda97f11287b086c17dbae432748e51e0e4d23"
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
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def branch(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=method(pe,ss,LOAD_RVA);st=method(pe,ss,SET_RVA);parent=method(pe,ss,PARENT_RVA)
 if len(c)!=84 or hashlib.sha256(c).hexdigest()!=LOAD_SHA:raise E("Load_SystemSe body")
 if len(st)!=8 or hashlib.sha256(st).hexdigest()!=SET_SHA:raise E("AudioClipInfo.Set body")
 if hashlib.sha256(parent).hexdigest()!=PARENT_SHA:raise E("FACT-0160 caller")
 if c[0:2]!=bytes([0x16,0x0A]):raise E("i=0")
 branch(c,0x0002,0x38,0x0046,"initial loop jump")
 tok(c,0x0007,0x7E,0x040086F4,"audioClipInfo")
 if c[0x000C:0x000E]!=bytes([0x06,0x9A]):raise E("audioClipInfo[i]")
 tok(c,0x000E,0x7B,0x0400874B,"audioClip field")
 if c[0x0013]!=0x14:raise E("null")
 tok(c,0x0014,0x28,0x0A00000F,"Object.op_Inequality")
 branch(c,0x0019,0x39,0x0023,"nonnull test")
 branch(c,0x001E,0x38,0x0042,"skip load")
 tok(c,0x0023,0x7E,0x040086E8,"SystemSEFileList")
 if c[0x0028:0x002A]!=bytes([0x06,0x9A]):raise E("SystemSEFileList[i]")
 tok(c,0x002A,0x28,0x0A0006DA,"Resources.Load")
 tok(c,0x002F,0x74,0x01000012,"cast AudioClip")
 if c[0x0034]!=0x0B:raise E("clip local1")
 tok(c,0x0035,0x7E,0x040086F4,"audioClipInfo #2")
 if c[0x003A:0x003D]!=bytes([0x06,0x9A,0x07]):raise E("setter receiver/arg")
 tok(c,0x003D,0x6F,0x060052C2,"AudioClipInfo.Set")
 if c[0x0042:0x0046]!=bytes([0x06,0x17,0x58,0x0A]):raise E("i++")
 if c[0x0046]!=0x06:raise E("loop i")
 tok(c,0x0047,0x7E,0x040086E8,"loop list")
 if c[0x004C:0x004E]!=bytes([0x8E,0x69]):raise E("Length conv.i4")
 branch(c,0x004E,0x3F,0x0007,"loop blt")
 if c[0x0053]!=0x2A:raise E("ret")
 if st!=bytes.fromhex("02037d4b8700042a"):raise E("Set writer")
 tok(parent,0x0097,0x28,0x06005283,"FACT-0160 caller #1")
 tok(parent,0x00E6,0x28,0x06005283,"FACT-0160 caller #2")
 print("PROVE_MENU_SOUND_LOAD_SYSTEM_SE: PASS")
if __name__=="__main__":main()
