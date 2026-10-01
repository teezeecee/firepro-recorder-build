#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006CA54
SIZE=132
CODE_SHA="f49006bbea8bcc23f4ac9019fc646d7fd2dc09edad531bc204b027a920bcc8c2"
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
 if m["max_stack"]!=2 or m["local_sig"]!=0x110002E1:raise E("header")
 if c[0]!=0x02:raise E("this")
 tok(c,0x0001,0x28,0x06001192,"FACT-0114 IsDLC")
 br(c,0x0006,0x3A,0x000D,"IsDLC true")
 if c[0x000B:0x000D]!=bytes([0x17,0x2A]):raise E("not DLC true return")
 if c[0x000D:0x000F]!=bytes([0x16,0x0A]):raise E("index init")
 br(c,0x000F,0x38,0x007A,"loop condition entry")
 if c[0x0014]!=0x02:raise E("this dlc")
 tok(c,0x0015,0x7B,0x04000FB8,"dlc field")
 if c[0x001A:0x001C]!=bytes([0x06,0x91]):raise E("dlc[index]")
 br(c,0x001C,0x39,0x0076,"dlc false")
 tok(c,0x0021,0x7E,0x040064EC,"SaveData.inst")
 if c[0x0026]!=0x06:raise E("DLC index arg")
 tok(c,0x0027,0x6F,0x060051C9,"IsDLCInstalled")
 br(c,0x002C,0x39,0x0076,"not installed")
 if c[0x0031:0x0033]!=bytes([0x06,0x1F]) or c[0x0033]!=0x09:raise E("raw index9")
 br(c,0x0034,0x40,0x0074,"index != 9")
 tok(c,0x0039,0x7E,0x0400497D,"StorySaveDataManager.inst")
 if c[0x003E]!=0x18:raise E("raw story2")
 tok(c,0x003F,0x6F,0x06003C25,"FACT-0104 GetStoryData")
 if c[0x0044]!=0x0B:raise E("story local")
 if c[0x0045]!=0x07:raise E("story load")
 br(c,0x0046,0x39,0x0058,"story null")
 if c[0x004B]!=0x07:raise E("story load #2")
 tok(c,0x004C,0x7B,0x0400485A,"m_root_clear")
 br(c,0x0051,0x39,0x0058,"root clear false")
 if c[0x0056:0x0058]!=bytes([0x17,0x2A]):raise E("root true return")
 tok(c,0x0058,0x28,0x06001FC1,"GlobalParam.IsStoryMode")
 br(c,0x005D,0x39,0x006F,"not story mode")
 tok(c,0x0062,0x7E,0x04004856,"StoryWork.storyScenario")
 if c[0x0067]!=0x18:raise E("storyScenario raw2")
 br(c,0x0068,0x40,0x006F,"scenario != 2")
 if c[0x006D:0x006F]!=bytes([0x17,0x2A]):raise E("scenario true return")
 br(c,0x006F,0x38,0x0076,"special continue")
 if c[0x0074:0x0076]!=bytes([0x17,0x2A]):raise E("non9 true return")
 if c[0x0076:0x007A]!=bytes([0x06,0x17,0x58,0x0A]):raise E("index increment")
 if c[0x007A:0x007D]!=bytes([0x06,0x1F,0x0D]):raise E("index/raw13")
 br(c,0x007D,0x3F,0x0014,"signed index < 13")
 if c[0x0082:0x0084]!=bytes([0x16,0x2A]):raise E("false return")
 tok(cc,0x0025,0x6F,0x06001191,"FACT-0111 caller")
 print("PROVE_THEME_MUSIC_INFO_CHECK_VALIDATION_DLC: PASS")
if __name__=="__main__":main()
