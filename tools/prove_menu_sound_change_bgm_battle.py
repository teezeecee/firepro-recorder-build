#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003224E8; SHA="4ad21fa3a9b1dd5d1b2e36c8c169c7d9809a762ca4958bbb3649036346facc9e"
GET_RVA=0x00320266; GET_SHA="46a9d4d199f469f19a3c443ea30af3a1a2d46348d9781332c319c4a5d83f9b3c"
PARENT_RVA=0x003218E4; PARENT_SHA="a9e694a8e4472424719df74de8cf44737e837e6a86bc7e5dfd2a29c6ee47931a"
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
 ss=sections(pe);c=body(pe,ss,RVA);g=body(pe,ss,GET_RVA);p=body(pe,ss,PARENT_RVA)
 if len(c)!=327 or hashlib.sha256(c).hexdigest()!=SHA:raise E("Change_BGM_Battle")
 if len(g)!=8 or hashlib.sha256(g).hexdigest()!=GET_SHA or g!=bytes.fromhex("7e2e860004029a2a"):raise E("GetBGMInfo_Match")
 if hashlib.sha256(p).hexdigest()!=PARENT_SHA:raise E("FACT-0161")
 tok(c,0x0001,0x28,0x0600526F,"GetBGMInfo_Match")
 br(c,0x0008,0x39,0x007F,"async split")
 tok(c,0x000E,0x80,0x04008703,"async continue false")
 tok(c,0x0015,0x80,0x04008702,"async keep 15")
 tok(c,0x001B,0x7B,0x0400862C,"async asset_dir")
 tok(c,0x0020,0x28,0x0A000015,"IsNullOrEmpty async")
 br(c,0x0025,0x3A,0x0056,"async empty")
 tok(c,0x0036,0x28,0x0A000012,"Concat async bundle")
 tok(c,0x003C,0x28,0x0600527C,"FACT-0112 async bundle")
 tok(c,0x0046,0x28,0x06005295,"FACT-0115 bundle")
 tok(c,0x004B,0x6F,0x0A00035A,"StartCoroutine bundle")
 tok(c,0x0056,0x28,0x0600527C,"FACT-0112 async resource")
 tok(c,0x005B,0x72,0x7008EAFC,"Sound/Bgm async")
 tok(c,0x006F,0x28,0x06005294,"FACT-0115 resource")
 tok(c,0x0074,0x6F,0x0A00035A,"StartCoroutine resource")
 tok(c,0x0080,0x7B,0x0400862C,"sync asset_dir")
 tok(c,0x0085,0x28,0x0A000015,"IsNullOrEmpty sync")
 br(c,0x008A,0x3A,0x010E,"sync empty")
 tok(c,0x009B,0x28,0x0A000012,"Concat sync bundle")
 tok(c,0x00A0,0x28,0x0A000799,"LoadFromFile")
 tok(c,0x00A8,0x28,0x0A00000F,"Object inequality")
 br(c,0x00AD,0x39,0x00DE,"bundle null")
 tok(c,0x00B9,0x28,0x0A00071A,"Path.GetFileName")
 tok(c,0x00BE,0x6F,0x2B000100,"LoadAsset AudioClip")
 tok(c,0x00C4,0x7E,0x040086F4,"audioClipInfo bundle")
 tok(c,0x00CD,0x6F,0x060052C2,"FACT-0113 bundle")
 tok(c,0x00D4,0x6F,0x0A00079E,"bundle Unload")
 tok(c,0x00DE,0x72,0x7008EAFC,"Sound/Bgm fallback")
 tok(c,0x00EE,0x28,0x0A0006DA,"Resources.Load fallback")
 tok(c,0x00FA,0x7E,0x040086F4,"audioClipInfo fallback")
 tok(c,0x0104,0x6F,0x060052C2,"FACT-0113 fallback")
 tok(c,0x010E,0x72,0x7008EAFC,"Sound/Bgm empty")
 tok(c,0x011E,0x28,0x0A0006DA,"Resources.Load empty")
 tok(c,0x012A,0x7E,0x040086F4,"audioClipInfo empty")
 tok(c,0x0134,0x6F,0x060052C2,"FACT-0113 empty")
 tok(c,0x013A,0x80,0x04008703,"sync continue false")
 tok(c,0x0141,0x80,0x04008702,"sync keep 15")
 if c[0x0146]!=0x2A:raise E("ret")
 tok(p,0x0024,0x28,0x0600529A,"FACT-0161 caller")
 print("PROVE_MENU_SOUND_CHANGE_BGM_BATTLE: PASS")
if __name__=="__main__":main()
