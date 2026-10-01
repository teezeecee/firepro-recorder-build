#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x00309428,156,"e71d1708191a0dc125367efbaa8adb8c280f8e1068cf6ae26ea320a98d482d8b"),
 "Caller":(0x00309544,168,"14d88238c271a882dd9fe1c4d3a0fdd732d43a830be6728478f50747326aab9f")
}
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 tok(c,0x0000,0x7E,0x0400576C,"MatchMain.inst")
 if c[0x0005]!=0x0A:raise E("MatchMain local")
 if c[0x0006:0x000A]!=bytes([0x15,0x0B,0x16,0x0C]):raise E("selected=-1,index=0")
 br(c,0x000A,0x38,0x0051,"initial loop branch")
 tok(c,0x000F,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0014]!=0x08:raise E("index lookup")
 tok(c,0x0015,0x6F,0x06005065,"GetPlObj")
 if c[0x001A:0x001C]!=bytes([0x0D,0x09]):raise E("player local")
 tok(c,0x001C,0x28,0x0A00002A,"Player implicit")
 br(c,0x0021,0x3A,0x002B,"player true")
 br(c,0x0026,0x38,0x004D,"player false continue")
 if c[0x002B]!=0x09:raise E("player sleep")
 tok(c,0x002C,0x7B,0x04006057,"isSleep")
 br(c,0x0031,0x39,0x003B,"sleep zero")
 br(c,0x0036,0x38,0x004D,"sleep continue")
 if c[0x003B]!=0x09:raise E("player CheckRight")
 tok(c,0x003C,0x6F,0x06004EB9,"Player.CheckRight")
 br(c,0x0041,0x39,0x004D,"CheckRight false")
 if c[0x0046:0x0048]!=bytes([0x08,0x0B]):raise E("selected=index")
 br(c,0x0048,0x38,0x0058,"selection break")
 if c[0x004D:0x0051]!=bytes([0x08,0x17,0x58,0x0C]):raise E("index increment")
 if c[0x0051:0x0054]!=bytes([0x08,0x1E,0x3F]):raise E("index<8")
 if struct.unpack_from("<i",c,0x0054)[0]!=(0x000F-0x0058):raise E("loop target")
 if c[0x0058:0x005A]!=bytes([0x07,0x16]):raise E("selected>=0")
 br(c,0x005A,0x3C,0x0060,"selected nonnegative")
 if c[0x005F]!=0x2A:raise E("no selection return")
 if c[0x0060:0x0062]!=bytes([0x06,0x07]):raise E("SetAfterMatchBGM args")
 tok(c,0x0062,0x6F,0x06004924,"SetAfterMatchBGM")
 tok(c,0x0067,0x7E,0x040054C9,"Audience.inst #1")
 if c[0x006C]!=0x1A:raise E("SetBaseCheerLevel raw4")
 tok(c,0x006D,0x6F,0x060047D8,"SetBaseCheerLevel")
 tok(c,0x0072,0x7E,0x040054C9,"Audience.inst #2")
 if c[0x0077:0x0079]!=bytes([0x1A,0x17]):raise E("PlayLoop raw4 true")
 tok(c,0x0079,0x6F,0x060047DA,"FACT-0081 PlayLoopCheerVoice")
 tok(c,0x007E,0x7E,0x040054C9,"Audience.inst #3")
 if c[0x0083:0x0085]!=bytes([0x1C,0x1A]):raise E("PlayCheer raw6 raw4")
 tok(c,0x0085,0x6F,0x060047D9,"FACT-0079 PlayCheerVoice")
 tok(c,0x008A,0x7E,0x0400576C,"MatchMain.inst final")
 if c[0x008F]!=0x02:raise E("referee this result")
 tok(c,0x0090,0x7B,0x040062CD,"matchResult")
 if c[0x0095]!=0x07:raise E("selected final")
 tok(c,0x0096,0x6F,0x06004928,"ProcessMatchEnd_Normal")
 if c[0x009B]!=0x2A:raise E("ret")
 tok(cs["Caller"],0x00A2,0x28,0x060050A7,"FACT-0091 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"scan_indices":[0,7],"direct_callers":1}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_PROCESS_MATCH_END_NORMAL: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_PROCESS_MATCH_END_NORMAL: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
