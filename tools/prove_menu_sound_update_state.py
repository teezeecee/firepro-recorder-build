#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
UPDATE_RVA=0x00321910
UPDATE_SHA="0f78bdbd8f0a3abc281912645f9d95b9b3f182a1eae9bf24c948379d3782b6d5"
GET_RVA=0x003149C8
GET_SHA="2e12171cc208596025d626b80263f5597a296cc70ab5856f40c8660292702f40"
PARENT_RVA=0x003218E4
PARENT_SHA="a9e694a8e4472424719df74de8cf44737e837e6a86bc7e5dfd2a29c6ee47931a"
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
 ss=sections(pe);c=body(pe,ss,UPDATE_RVA);g=body(pe,ss,GET_RVA);parent=body(pe,ss,PARENT_RVA)
 if len(c)!=180 or hashlib.sha256(c).hexdigest()!=UPDATE_SHA:raise E("Update_State body")
 if len(g)!=6 or hashlib.sha256(g).hexdigest()!=GET_SHA:raise E("SaveData.GetInst body")
 if hashlib.sha256(parent).hexdigest()!=PARENT_SHA:raise E("FACT-0161 caller")
 tok(c,0x0000,0x28,0x06005174,"GetInst null gate")
 if c[0x0005]!=0x14:raise E("null")
 tok(c,0x0006,0x28,0x0A000006,"Object.op_Equality")
 if c[0x000B]!=0x39 or 0x000B+5+struct.unpack_from("<i",c,0x000C)[0]!=0x0011:raise E("null branch")
 if c[0x0010]!=0x2A:raise E("null return")
 rows=[
  (0x0011,0x0016,0x001B,0x040064C6,0x0021,0x0027,0x040086EE),
  (0x002C,0x0031,0x0036,0x040064C7,0x003C,0x0042,0x040086EF),
  (0x0047,0x004C,0x0051,0x040064C8,0x0057,0x005D,0x040086F0),
  (0x0062,0x0067,0x006C,0x040064C9,0x0072,0x0078,0x040086F1),
  (0x007D,0x0082,0x0087,0x040064CA,0x008D,0x0093,0x040086F2),
  (0x0098,0x009D,0x00A2,0x040064CB,0x00A8,0x00AE,0x040086F3)
 ]
 for gi,oi,si,src,ci,ti,dst in rows:
  tok(c,gi,0x28,0x06005174,"GetInst")
  tok(c,oi,0x7B,0x040064F2,"optionSettings")
  tok(c,si,0x7B,src,"source volume")
  if c[si+5]!=0x6B:raise E("conv.r4")
  if c[ci]!=0x22 or struct.unpack_from("<f",c,ci+1)[0]!=100.0:raise E("100.0f")
  if c[ci+5]!=0x5B:raise E("div")
  tok(c,ti,0x80,dst,"target volume")
 if c[0x00B3]!=0x2A:raise E("final ret")
 if g[0]!=0x7E or struct.unpack_from("<I",g,1)[0]!=0x040064EC or g[5]!=0x2A:raise E("GetInst field leaf")
 tok(parent,0x0000,0x28,0x06005282,"FACT-0161 caller")
 print("PROVE_MENU_SOUND_UPDATE_STATE: PASS")
if __name__=="__main__":main()
