#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003220C0
SHA="29648ba9313068964c8561e9f85d81f876629060fb99ee22e3b18e160e3b77b5"
GET_RVA=0x0032025D
GET_SHA="9cd18fdda1bfb9a6545243b98a151f8e8bc2fd604a36f2611c82a99548ff4eb2"
PARENT_RVA=0x003218E4
PARENT_SHA="a9e694a8e4472424719df74de8cf44737e837e6a86bc7e5dfd2a29c6ee47931a"
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
 ss=sections(pe);c=body(pe,ss,RVA);g=body(pe,ss,GET_RVA);parent=body(pe,ss,PARENT_RVA)
 if len(c)!=269 or hashlib.sha256(c).hexdigest()!=SHA:raise E("Change_BGM_Progress")
 if len(g)!=8 or hashlib.sha256(g).hexdigest()!=GET_SHA:raise E("GetBGMInfo_Menu")
 if hashlib.sha256(parent).hexdigest()!=PARENT_SHA:raise E("FACT-0161 caller")
 tok(c,0x0000,0x28,0x06005282,"FACT-0163 Update_State")
 tok(c,0x0005,0x7E,0x04008702,"g_KeepBgmNumber")
 br(c,0x000B,0x3B,0x00F8,"same index")
 br(c,0x0011,0x39,0x0082,"sync split")
 tok(c,0x0017,0x80,0x04008702,"keep async")
 tok(c,0x001D,0x28,0x0600526E,"GetBGMInfo async")
 tok(c,0x0024,0x80,0x04008703,"continue false async")
 br(c,0x002B,0x3D,0x0059,"async raw5 split")
 tok(c,0x0035,0x72,0x7008EAFC,"Sound/Bgm async")
 tok(c,0x003B,0x7B,0x04008629,"fileName async")
 tok(c,0x0049,0x28,0x06005294,"FACT-0115 async low")
 tok(c,0x004E,0x6F,0x0A00035A,"StartCoroutine low")
 tok(c,0x005E,0x72,0x7008EB12,"Organization async")
 tok(c,0x0064,0x7B,0x04008629,"fileName async high")
 tok(c,0x0072,0x28,0x06005294,"FACT-0115 async high")
 tok(c,0x0077,0x6F,0x0A00035A,"StartCoroutine high")
 tok(c,0x0083,0x80,0x04008702,"keep sync")
 tok(c,0x0089,0x28,0x0600526E,"GetBGMInfo sync")
 br(c,0x0091,0x3D,0x00C4,"sync raw5 split")
 tok(c,0x0096,0x72,0x7008EAFC,"Sound/Bgm sync")
 tok(c,0x009C,0x7B,0x04008629,"fileName sync")
 tok(c,0x00A6,0x28,0x0A0006DA,"Resources.Load low")
 tok(c,0x00AB,0x74,0x01000012,"AudioClip cast low")
 tok(c,0x00B1,0x7E,0x040086F4,"audioClipInfo low")
 tok(c,0x00BA,0x6F,0x060052C2,"FACT-0113 Set low")
 tok(c,0x00C4,0x72,0x7008EB12,"Organization sync")
 tok(c,0x00CA,0x7B,0x04008629,"fileName sync high")
 tok(c,0x00D4,0x28,0x0A0006DA,"Resources.Load high")
 tok(c,0x00D9,0x74,0x01000012,"AudioClip cast high")
 tok(c,0x00DF,0x7E,0x040086F4,"audioClipInfo high")
 tok(c,0x00E8,0x6F,0x060052C2,"FACT-0113 Set high")
 tok(c,0x00EE,0x80,0x04008703,"continue false sync")
 br(c,0x00F3,0x38,0x010C,"return join")
 if c[0x00F8]!=0x04:raise E("same bStart")
 br(c,0x00F9,0x39,0x0106,"same bStart false")
 if c[0x00FE:0x0101]!=bytes([0x1F,0x20,0x17]):raise E("raw32/raw1")
 tok(c,0x0101,0x28,0x0600529E,"FACT-0132 Play_BGM")
 if c[0x0106]!=0x17:raise E("continue true")
 tok(c,0x0107,0x80,0x04008703,"continue true store")
 if c[0x010C]!=0x2A:raise E("ret")
 if g!=bytes.fromhex("7e2d860004029a2a"):raise E("BGMInfo_Menu getter")
 tok(parent,0x000C,0x28,0x06005292,"FACT-0161 caller")
 print("PROVE_MENU_SOUND_CHANGE_BGM_PROGRESS: PASS")
if __name__=="__main__":main()
