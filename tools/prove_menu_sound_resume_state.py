#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003218E4
SIZE=42
CODE_SHA="a9e694a8e4472424719df74de8cf44737e837e6a86bc7e5dfd2a29c6ee47931a"
CALLER_RVA=0x003217EC
CALLER_SHA="11a01435a5eb88584d4a811a33bda97f11287b086c17dbae432748e51e0e4d23"
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
 ss=sections(pe);c=body(pe,ss,RVA);parent=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("Resume_State body")
 if hashlib.sha256(parent).hexdigest()!=CALLER_SHA:raise E("FACT-0160 caller")
 tok(c,0x0000,0x28,0x06005282,"Update_State")
 tok(c,0x0005,0x7E,0x0400286D,"BattleConfig_BGM_Progress")
 if c[0x000A:0x000C]!=bytes([0x16,0x16]):raise E("progress raw zero args")
 tok(c,0x000C,0x28,0x06005292,"Change_BGM_Progress")
 tok(c,0x0011,0x7E,0x0400286E,"BattleConfig_BGM_Admission")
 if c[0x0016:0x0018]!=bytes([0x16,0x16]):raise E("theme raw zero args")
 tok(c,0x0018,0x28,0x06005296,"Change_BGM_Theme")
 tok(c,0x001D,0x7E,0x0400286F,"BattleConfig_BGM_Battle")
 if c[0x0022:0x0024]!=bytes([0x16,0x16]):raise E("battle raw zero args")
 tok(c,0x0024,0x28,0x0600529A,"Change_BGM_Battle")
 if c[0x0029]!=0x2A:raise E("ret")
 tok(parent,0x0092,0x28,0x06005281,"FACT-0160 caller")
 print("PROVE_MENU_SOUND_RESUME_STATE: PASS")
if __name__=="__main__":main()
