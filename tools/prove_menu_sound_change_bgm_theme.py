#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00322268
SIZE=399
CODE_SHA="2e0905ada32d6f97c3a3ac37f28bb0722b6084a109618070cf1dfc1ea1fb4733"
CALLER_RVA=0x00299808
CALLER_SHA="c64099c6e74a32eaa9dcc01c14768a9687140d2da506f443bd11da9449a5bb58"
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
 if m["max_stack"]!=5 or m["local_sig"]!=0x11001202:raise E("header")
 tok(c,0x0001,0x7E,0x04000FBC,"ThemeMusicInfoManager.inst #1")
 tok(c,0x0006,0x7B,0x04000FBD,"themeMusicList")
 tok(c,0x000B,0x6F,0x0A000B98,"theme list Count")
 br(c,0x0010,0x3F,0x0018,"index below Count")
 if c[0x0015:0x0018]!=bytes([0x16,0x10,0x00]):raise E("index=0")
 tok(c,0x0018,0x7E,0x04000FBC,"ThemeMusicInfoManager.inst #2")
 tok(c,0x001E,0x6F,0x06001196,"GetThemeMusicInfo #1")
 tok(c,0x0025,0x6F,0x06001191,"CheckValidationDLC")
 br(c,0x002A,0x3A,0x003B,"validation true")
 tok(c,0x002F,0x7E,0x04000FBC,"ThemeMusicInfoManager.inst fallback")
 tok(c,0x0035,0x6F,0x06001196,"GetThemeMusicInfo fallback")
 br(c,0x003C,0x39,0x00B7,"bAsync false")
 tok(c,0x0042,0x80,0x04008703,"g_ProgressBGM_Continue async")
 tok(c,0x0049,0x80,0x04008702,"g_KeepBgmNumber async")
 tok(c,0x004E,0x7E,0x0A000025,"String.Empty async")
 tok(c,0x0053,0x80,0x04008705,"MyMusic_SelectFile_Admission async")
 tok(c,0x0059,0x6F,0x06001192,"IsDLC async")
 br(c,0x005E,0x39,0x008E,"async non-DLC")
 tok(c,0x0063,0x72,0x700649B3,"DLC path")
 tok(c,0x0069,0x7B,0x04000FBA,"fileName DLC async")
 tok(c,0x0074,0x28,0x0600527C,"get__instance #1")
 tok(c,0x007E,0x28,0x06005295,"CoChange bundle")
 tok(c,0x008E,0x28,0x0600527C,"get__instance #2")
 tok(c,0x0093,0x72,0x7008EAFC,"resource path async")
 tok(c,0x0099,0x7B,0x04000FBA,"fileName resource async")
 tok(c,0x00A7,0x28,0x06005294,"CoChange normal")
 tok(c,0x00B8,0x6F,0x06001192,"IsDLC sync")
 br(c,0x00BD,0x39,0x014C,"sync non-DLC")
 tok(c,0x00C2,0x72,0x700649B3,"DLC path sync")
 tok(c,0x00C8,0x7B,0x04000FBA,"fileName DLC sync")
 tok(c,0x00D2,0x28,0x0A000799,"AssetBundle.LoadFromFile")
 br(c,0x00DF,0x39,0x0110,"bundle null")
 tok(c,0x00E6,0x7B,0x04000FBA,"fileName asset")
 tok(c,0x00EB,0x28,0x0A00071A,"Path.GetFileName")
 tok(c,0x00F0,0x6F,0x2B000100,"LoadAsset methodspec")
 tok(c,0x00F6,0x7E,0x040086F4,"audioClipInfo #1")
 tok(c,0x00FF,0x6F,0x060052C2,"AudioClipInfo.Set #1")
 tok(c,0x0106,0x6F,0x0A00079E,"AssetBundle.Unload")
 tok(c,0x0110,0x7E,0x04000FBC,"ThemeMusicInfoManager.inst bundle fallback")
 tok(c,0x0116,0x6F,0x06001196,"GetThemeMusicInfo bundle fallback")
 tok(c,0x011C,0x72,0x7008EAFC,"resource path bundle fallback")
 tok(c,0x0122,0x7B,0x04000FBA,"fileName bundle fallback")
 tok(c,0x012C,0x28,0x0A0006DA,"Resources.Load #1")
 tok(c,0x0138,0x7E,0x040086F4,"audioClipInfo #2")
 tok(c,0x0142,0x6F,0x060052C2,"AudioClipInfo.Set #2")
 tok(c,0x014C,0x72,0x7008EAFC,"resource path non-DLC")
 tok(c,0x0152,0x7B,0x04000FBA,"fileName non-DLC")
 tok(c,0x015C,0x28,0x0A0006DA,"Resources.Load #2")
 tok(c,0x0168,0x7E,0x040086F4,"audioClipInfo #3")
 tok(c,0x0172,0x6F,0x060052C2,"AudioClipInfo.Set #3")
 tok(c,0x0178,0x80,0x04008703,"g_ProgressBGM_Continue tail")
 tok(c,0x017F,0x80,0x04008702,"g_KeepBgmNumber tail")
 tok(c,0x0184,0x7E,0x0A000025,"String.Empty tail")
 tok(c,0x0189,0x80,0x04008705,"MyMusic_SelectFile_Admission tail")
 if c[0x018E]!=0x2A:raise E("ret")
 for off in (0x003E,0x00B8,0x00EE):tok(cc,off,0x28,0x06005296,"FACT-0108 caller")
 print("PROVE_MENU_SOUND_CHANGE_BGM_THEME: PASS")
if __name__=="__main__":main()
