#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x003081C4,258,"3688c9d5342ef0785ee92923ceb8862dc82d0e50d0aaa26e580f3487c9502f4b"),
 "Arrived":(0x00308668,545,"ec45a72452fcbddd71df0a05d3c7b9a68df75fa36c1452a36638468a5e9db5e4")
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
def f32bits(c,o,b,l):
 if c[o]!=0x22 or struct.unpack_from("<I",c,o+1)[0]!=b:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 tok(c,0x0000,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0005]!=0x02:raise E("this target")
 tok(c,0x0006,0x7B,0x040062A4,"TargetPlIdx")
 tok(c,0x000B,0x6F,0x06005065,"GetPlObj")
 if c[0x0010:0x0012]!=bytes([0x0A,0x06]):raise E("player local")
 tok(c,0x0012,0x28,0x0A00002A,"Player implicit")
 br(c,0x0017,0x3A,0x001D,"player true")
 if c[0x001C]!=0x2A:raise E("player false return")
 if c[0x001D]!=0x06:raise E("player isPinfallDef")
 tok(c,0x001E,0x7B,0x04006049,"isPinfallDef")
 br(c,0x0023,0x3A,0x002F,"isPinfallDef true")
 if c[0x0028]!=0x02:raise E("SetFree this")
 tok(c,0x0029,0x28,0x06005095,"SetFree")
 if c[0x002E]!=0x2A:raise E("SetFree return")
 tok(c,0x002F,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x0034,0x7B,0x04002AD2,"MatchSetting")
 if c[0x0039:0x003B]!=bytes([0x0B,0x07]):raise E("matchsetting local")
 tok(c,0x003B,0x7B,0x040057F1,"isRopeCheck")
 br(c,0x0040,0x39,0x00B8,"rope false normal")
 tok(c,0x0045,0x7E,0x04006355,"Ring.inst")
 f32bits(c,0x004A,0x3F2AAAB0,"collision float")
 if c[0x004F]!=0x06:raise E("player pos")
 tok(c,0x0050,0x7B,0x04005FAA,"Player.PlPos")
 tok(c,0x0055,0x28,0x0A000089,"Vector2 implicit")
 tok(c,0x005A,0x6F,0x060050EE,"ring collision")
 br(c,0x005F,0x39,0x00B8,"collision false normal")
 if c[0x0064]!=0x06:raise E("player animator")
 tok(c,0x0065,0x7B,0x04005FA8,"Player.animator")
 if c[0x006A]!=0x17:raise E("loopend one")
 tok(c,0x006B,0x7D,0x04005EE5,"isReqAnmLoopEnd")
 if c[0x0070:0x0072]!=bytes([0x06,0x16]):raise E("SetDownTime0")
 tok(c,0x0072,0x6F,0x06004ED8,"FACT-0029 SetDownTime")
 if c[0x0077:0x007A]!=bytes([0x02,0x1F,0x17]):raise E("State23")
 tok(c,0x007A,0x7D,0x0400629D,"State field rope")
 tok(c,0x0082,0x7B,0x040062A4,"TargetPlIdx rope")
 tok(c,0x0087,0x28,0x0600508C,"FACT-0086 DecideRefereeDir rope")
 tok(c,0x008C,0x7D,0x040062A3,"PlDir rope")
 tok(c,0x0092,0x7E,0x04006297,"RefAnmTbl")
 if c[0x0097:0x009A]!=bytes([0x1F,0x21,0x7E]):raise E("raw33 / 2dir load")
 if struct.unpack_from("<I",c,0x009A)[0]!=0x0400565C:raise E("AnmOfsTbl_2Dir rope")
 tok(c,0x00A7,0x28,0x06005096,"FACT-0068 ReqRefereeAnm rope")
 tok(c,0x00AC,0x7E,0x040086E4,"MatchSEPlayer.inst")
 if c[0x00B1]!=0x17:raise E("voice raw1")
 tok(c,0x00B2,0x6F,0x06005279,"FACT-0076 PlayRefereeVoice")
 if c[0x00B7]!=0x2A:raise E("rope return")
 if c[0x00B8:0x00BB]!=bytes([0x02,0x1F,0x09]):raise E("State9")
 tok(c,0x00BB,0x7D,0x0400629D,"State normal")
 tok(c,0x00C3,0x7B,0x040062A4,"TargetPlIdx normal")
 tok(c,0x00C8,0x28,0x0600508C,"FACT-0086 DecideRefereeDir normal")
 tok(c,0x00CD,0x7D,0x040062A3,"PlDir normal")
 tok(c,0x00D3,0x7E,0x0400629A,"AnmIDTbl_FallCount")
 tok(c,0x00D8,0x7E,0x0400565C,"AnmOfsTbl_2Dir normal")
 tok(c,0x00DE,0x7B,0x040062A3,"PlDir normal table")
 tok(c,0x00E5,0x28,0x06005096,"FACT-0068 ReqRefereeAnm normal")
 if c[0x00EA]!=0x02:raise E("FrameWait this")
 tok(c,0x00EB,0x7E,0x04006289,"FallWaitCnt")
 tok(c,0x00F1,0x7B,0x040062C3,"RefePrm")
 tok(c,0x00F6,0x7B,0x04000E71,"fallCount")
 if c[0x00FB]!=0x94:raise E("FallWaitCnt index")
 tok(c,0x00FC,0x7D,0x040062B4,"FrameWait")
 if c[0x0101]!=0x2A:raise E("final ret")
 tok(cs["Arrived"],0x005B,0x28,0x0600509A,"FACT-0085 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"states":[23,9],"collision_bits":"0x3F2AAAB0"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_START_FALL_COUNT: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_START_FALL_COUNT: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
