#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00299808
SIZE=244
CODE_SHA="c64099c6e74a32eaa9dcc01c14768a9687140d2da506f443bd11da9449a5bb58"
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
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 m=method(pe,sections(pe),RVA);c=m["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["max_stack"]!=3 or m["local_sig"]!=0x11000EED:raise E("header")
 tok(c,0x0001,0x7B,0x04005553,"plIdxList")
 tok(c,0x0007,0x7B,0x04005555,"plNum")
 if c[0x000C:0x000F]!=bytes([0x17,0x59,0x94]):raise E("plNum-1/index")
 tok(c,0x0010,0x7E,0x040061FA,"PlayerMan.inst")
 tok(c,0x0016,0x6F,0x06005065,"GetPlObj")
 tok(c,0x001D,0x7B,0x04005FB3,"WresParam #1")
 tok(c,0x0022,0x7B,0x040010A0,"themeMusic #1")
 i4(c,0x0027,10000,"theme raw10000")
 br(c,0x002C,0x3C,0x0048,"theme >=10000")
 tok(c,0x0032,0x7B,0x04005FB3,"WresParam #2")
 tok(c,0x0037,0x7B,0x040010A0,"themeMusic #2")
 if c[0x003C:0x003E]!=bytes([0x16,0x16]):raise E("false false #1")
 tok(c,0x003E,0x28,0x06005296,"Change_BGM_Theme #1")
 br(c,0x0043,0x38,0x00F3,"early return join")
 tok(c,0x0048,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x004D,0x7B,0x04002AD2,"MatchSetting")
 tok(c,0x0054,0x7B,0x040057CE,"matchWrestlerInfo")
 tok(c,0x005D,0x7B,0x040057BD,"wrestlerID #1")
 i4(c,0x0062,10000,"wrestler raw10000")
 br(c,0x0067,0x3C,0x0079,"wrestler >=10000")
 tok(c,0x006D,0x7B,0x040057BD,"wrestlerID #2")
 if c[0x0072:0x0074]!=bytes([0x1F,0xFE]):raise E("raw -2 #1")
 br(c,0x0074,0x40,0x00E1,"not -2 fallback")
 tok(c,0x0079,0x7E,0x040064EC,"SaveData.inst")
 tok(c,0x007F,0x7B,0x040057BD,"wrestlerID #3")
 tok(c,0x0084,0x6F,0x060051B9,"FACT-0102 GetEditWrestlerData")
 tok(c,0x008C,0x7B,0x040057BD,"wrestlerID #4")
 if c[0x0091:0x0093]!=bytes([0x1F,0xFE]):raise E("raw -2 #2")
 br(c,0x0093,0x40,0x00A4,"not -2 data keep")
 tok(c,0x0098,0x28,0x06005172,"FACT-0099 get_story_data")
 tok(c,0x009D,0x7B,0x0400489A,"story m_pc")
 tok(c,0x00A6,0x7B,0x040010C3,"ThemeMusic_Filename #1")
 tok(c,0x00AB,0x28,0x06002C1E,"FACT-0100 Check_File")
 br(c,0x00B0,0x3A,0x00CE,"file exists")
 if c[0x00B5:0x00B8]!=bytes([0x16,0x16,0x16]):raise E("zero false false")
 tok(c,0x00B8,0x28,0x06005296,"Change_BGM_Theme #2")
 if c[0x00BD:0x00BF]!=bytes([0x1F,0x21]):raise E("raw33 #1")
 tok(c,0x00BF,0x7E,0x0A000025,"String.Empty")
 tok(c,0x00C4,0x28,0x06002C23,"MyMusic.Set #1")
 br(c,0x00C9,0x38,0x00DC,"file false join")
 if c[0x00CE:0x00D0]!=bytes([0x1F,0x21]):raise E("raw33 #2")
 tok(c,0x00D2,0x7B,0x040010C3,"ThemeMusic_Filename #2")
 tok(c,0x00D7,0x28,0x06002C23,"MyMusic.Set #2")
 br(c,0x00DC,0x38,0x00F3,"music join")
 tok(c,0x00E2,0x7B,0x04005FB3,"WresParam #3")
 tok(c,0x00E7,0x7B,0x040010A0,"themeMusic #3")
 if c[0x00EC:0x00EE]!=bytes([0x16,0x16]):raise E("false false #3")
 tok(c,0x00EE,0x28,0x06005296,"Change_BGM_Theme #3")
 if c[0x00F3]!=0x2A:raise E("ret")
 print("PROVE_ENTRANCE_SCENE_INIT_THEME_MUSIC: PASS")
if __name__=="__main__":main()
