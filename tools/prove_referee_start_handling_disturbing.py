#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x00308528,202,"2b83b8d57051b7b88b861140401b12d2ec72246595a3021b601c6cc10754b96c"),
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
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
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
 tok(c,0x0000,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0005]!=0x02:raise E("this target")
 tok(c,0x0006,0x7B,0x040062A4,"TargetPlIdx")
 tok(c,0x000B,0x6F,0x06005065,"GetPlObj")
 if c[0x0010:0x0012]!=bytes([0x0A,0x06]):raise E("player local")
 tok(c,0x0012,0x28,0x0A00002A,"Player implicit")
 br(c,0x0017,0x3A,0x001D,"player true")
 if c[0x001C]!=0x2A:raise E("player false return")
 if c[0x001D:0x0020]!=bytes([0x02,0x1F,0x12]):raise E("State18")
 tok(c,0x0020,0x7D,0x0400629D,"State field")
 if c[0x0025:0x0028]!=bytes([0x02,0x02,0x02]):raise E("direction this chain")
 tok(c,0x0028,0x7B,0x040062A4,"TargetPlIdx direction")
 tok(c,0x002D,0x28,0x0600508C,"FACT-0086 DecideRefereeDir")
 tok(c,0x0032,0x7D,0x040062A3,"PlDir #1")
 if c[0x0037:0x0039]!=bytes([0x02,0x02]):raise E("reverse this")
 tok(c,0x0039,0x7B,0x040062A3,"PlDir reverse read")
 tok(c,0x003E,0x28,0x06004966,"ReversePlayerDirLR")
 tok(c,0x0043,0x7D,0x040062A3,"PlDir reverse store")
 i4(c,0x0048,1158,"default anm")
 if c[0x004D]!=0x0B:raise E("stloc1 anm")
 tok(c,0x004F,0x7B,0x040062A3,"PlDir compare1")
 if c[0x0054]!=0x17:raise E("raw PlDir1")
 br(c,0x0055,0x3B,0x0066,"PlDir==1")
 tok(c,0x005B,0x7B,0x040062A3,"PlDir compare5")
 if c[0x0060]!=0x1B:raise E("raw PlDir5")
 br(c,0x0061,0x40,0x006C,"PlDir!=5")
 i4(c,0x0066,1159,"replacement anm")
 if c[0x006B]!=0x0B:raise E("stloc1 replacement")
 if c[0x006C:0x006E]!=bytes([0x02,0x07]):raise E("request args")
 tok(c,0x006E,0x28,0x06005096,"FACT-0068 ReqRefereeAnm")
 if c[0x0073]!=0x02:raise E("disturbedCnt this")
 tok(c,0x0074,0x7E,0x0400628D,"DisturbedTime")
 tok(c,0x007A,0x7B,0x040062C3,"RefePrm")
 tok(c,0x007F,0x7B,0x04000E76,"interfereTime")
 if c[0x0084]!=0x94:raise E("DisturbedTime index")
 tok(c,0x0085,0x7D,0x040062C8,"disturbedCnt")
 if c[0x008A]!=0x06:raise E("player local animator1")
 tok(c,0x008B,0x7B,0x04005FA8,"Player.animator #1")
 if c[0x0090]!=0x06:raise E("player local animator2")
 tok(c,0x0091,0x7B,0x04005FA8,"Player.animator #2")
 tok(c,0x0096,0x7B,0x04005ED8,"BasicSkillID")
 if c[0x009B:0x009E]!=bytes([0x16,0x15,0x6F]):raise E("ReqBasicAnm false -1")
 if struct.unpack_from("<I",c,0x009E)[0]!=0x06004E6F:raise E("FACT-0010 ReqBasicAnm")
 if c[0x00A2]!=0x06:raise E("player local StartAnm")
 tok(c,0x00A3,0x7B,0x04005FA8,"Player.animator #3")
 if c[0x00A8]!=0x17:raise E("StartAnm raw1")
 tok(c,0x00A9,0x6F,0x06004E75,"FACT-0006 StartAnm")
 if c[0x00AE:0x00B0]!=bytes([0x06,0x17]):raise E("disturbingStep raw1")
 tok(c,0x00B0,0x7D,0x04006022,"disturbingStep")
 tok(c,0x00B5,0x7E,0x040086E4,"MatchSEPlayer.inst")
 if c[0x00BA:0x00BC]!=bytes([0x1F,0x15]):raise E("voice raw21")
 if c[0x00BC:0x00BE]!=bytes([0x16,0x19]):raise E("Range 0,3")
 tok(c,0x00BE,0x28,0x0600497B,"FACT-0032 Range")
 if c[0x00C3]!=0x58:raise E("voice add")
 tok(c,0x00C4,0x6F,0x06005279,"FACT-0076 PlayRefereeVoice")
 if c[0x00C9]!=0x2A:raise E("ret")
 tok(cs["Arrived"],0x0216,0x28,0x0600509D,"FACT-0085 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"animation_ids":[1158,1159],"voice_expression":"21+Range(0,3)"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_START_HANDLING_DISTURBING: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_START_HANDLING_DISTURBING: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
