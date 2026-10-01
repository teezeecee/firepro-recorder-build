#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Leaf":(0x002A95D8,195,"57fe61387e5df262b4c752819960c309b4a48a1a2299a231f8f5199a6e69eeb3"),"Caller":(0x00309428,156,"e71d1708191a0dc125367efbaa8adb8c280f8e1068cf6ae26ea320a98d482d8b")}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 tok(c,0x0000,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x0005,0x7B,0x04002AD2,"MatchSetting")
 tok(c,0x000B,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0010]!=0x03:raise E("pl_idx lookup")
 tok(c,0x0011,0x6F,0x06005065,"GetPlObj")
 if c[0x0017:0x0019]!=bytes([0x02,0x07]):raise E("theme receiver/player")
 tok(c,0x0019,0x7B,0x04005FB3,"WresParam")
 tok(c,0x001E,0x7B,0x040010A0,"themeMusic")
 tok(c,0x0023,0x7D,0x0400574D,"ThemeMusic")
 if c[0x0028]!=0x02:raise E("filename receiver")
 tok(c,0x0029,0x7E,0x0A000025,"String.Empty")
 tok(c,0x002E,0x7D,0x0400574E,"ThemeMusicFilename")
 if c[0x0033]!=0x06:raise E("MatchSetting local")
 tok(c,0x0034,0x7B,0x040057CE,"matchWrestlerInfo")
 if c[0x0039:0x003B]!=bytes([0x03,0x9A]):raise E("matchWrestlerInfo[pl_idx]")
 if c[0x003B:0x003E]!=bytes([0x0C,0x14,0x0D]):raise E("locals item/data")
 if c[0x003E]!=0x08:raise E("item wrestlerID")
 tok(c,0x003F,0x7B,0x040057BD,"wrestlerID #1")
 i4(c,0x0044,10000,"raw10000")
 br(c,0x0049,0x3F,0x0064,"wrestlerID <10000")
 tok(c,0x004E,0x7E,0x040064EC,"SaveData.inst")
 if c[0x0053]!=0x08:raise E("item edit")
 tok(c,0x0054,0x7B,0x040057BD,"wrestlerID #2")
 tok(c,0x0059,0x6F,0x060051B9,"GetEditWrestlerData")
 if c[0x005E]!=0x0D:raise E("data edit store")
 br(c,0x005F,0x38,0x007C,"edit join")
 if c[0x0064]!=0x08:raise E("item story")
 tok(c,0x0065,0x7B,0x040057BD,"wrestlerID #3")
 if c[0x006A:0x006C]!=bytes([0x1F,0xFE]):raise E("raw -2")
 br(c,0x006C,0x40,0x007C,"not story sentinel")
 tok(c,0x0071,0x28,0x06005172,"get_story_data")
 tok(c,0x0076,0x7B,0x0400489A,"m_pc")
 if c[0x007B:0x007D]!=bytes([0x0D,0x09]):raise E("story data local")
 br(c,0x007D,0x39,0x00C2,"null data return")
 if c[0x0082]!=0x09:raise E("data filename #1")
 tok(c,0x0083,0x7B,0x040010C3,"ThemeMusic_Filename #1")
 tok(c,0x0088,0x28,0x0A000015,"String.IsNullOrEmpty")
 br(c,0x008D,0x3A,0x00C2,"empty filename return")
 if c[0x0092]!=0x09:raise E("data filename #2")
 tok(c,0x0093,0x7B,0x040010C3,"ThemeMusic_Filename #2")
 tok(c,0x0098,0x28,0x06002C1E,"MyMusic.Check_File")
 br(c,0x009D,0x39,0x00BB,"file missing")
 if c[0x00A2:0x00A5]!=bytes([0x02,0x1F,0xFE]):raise E("ThemeMusic=-2 args")
 tok(c,0x00A5,0x7D,0x0400574D,"ThemeMusic=-2")
 if c[0x00AA:0x00AC]!=bytes([0x02,0x09]):raise E("filename copy args")
 tok(c,0x00AC,0x7B,0x040010C3,"ThemeMusic_Filename #3")
 tok(c,0x00B1,0x7D,0x0400574E,"ThemeMusicFilename copy")
 br(c,0x00B6,0x38,0x00C2,"success end")
 if c[0x00BB:0x00BD]!=bytes([0x02,0x16]):raise E("ThemeMusic=0 args")
 tok(c,0x00BD,0x7D,0x0400574D,"ThemeMusic=0")
 if c[0x00C2]!=0x2A:raise E("ret")
 cc=cs["Caller"]
 tok(cc,0x0062,0x6F,0x06004924,"FACT-0093 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"raw_edit_threshold":10000,"raw_story_sentinel":-2}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_MATCH_SET_AFTER_MATCH_BGM: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_MATCH_SET_AFTER_MATCH_BGM: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
