#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Arrived":(0x00308668,545,"ec45a72452fcbddd71df0a05d3c7b9a68df75fa36c1452a36638468a5e9db5e4"),
 "Move":(0x00308600,89,"58c6b30e276aa4ab2b5a5e4116f2f309ebb362cf4a6cb17d52245a744bd6fae1")
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
def sw(c,o,targets):
 if c[o]!=0x45:raise E("switch opcode")
 n=struct.unpack_from("<I",c,o+1)[0]
 if n!=len(targets):raise E("switch count")
 base=o+5+4*n
 got=[base+struct.unpack_from("<i",c,o+5+4*i)[0] for i in range(n)]
 if got!=targets:raise E("switch targets "+repr(got))
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Arrived"]
 tok(c,0x0000,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0005]!=0x02:raise E("this before TargetPlIdx")
 tok(c,0x0006,0x7B,0x040062A4,"TargetPlIdx")
 tok(c,0x000B,0x6F,0x06005065,"PlayerMan.GetPlObj")
 if c[0x0010:0x0012]!=bytes([0x0A,0x06]):raise E("player local")
 tok(c,0x0012,0x28,0x0A00002A,"Player implicit")
 if c[0x0017]!=0x3A or struct.unpack_from("<i",c,0x0018)[0]!=(0x001D-0x001C):raise E("player true branch")
 if c[0x001C]!=0x2A:raise E("player false return")
 tok(c,0x001E,0x7B,0x0400629F,"NextState")
 if c[0x0023:0x0028]!=bytes([0x0B,0x07,0x1F,0x09,0x59]):raise E("NextState-9")
 sw(c,0x0028,[0x005A,0x0199,0x00D6,0x0070,0x0115,0x0070,0x0065,0x0154,0x01DB,0x0215])
 tok(c,0x005B,0x28,0x0600509A,"Start_FallCount")
 tok(c,0x0066,0x28,0x0600509B,"Start_SubmissionCheck")
 if c[0x0070:0x0073]!=bytes([0x02,0x1F,0x0C]):raise E("State12 prefix")
 tok(c,0x0073,0x7D,0x0400629D,"State=12")
 tok(c,0x0079,0x7B,0x0400629F,"NextState case14")
 if c[0x007E:0x0080]!=bytes([0x1F,0x0E]):raise E("raw14")
 if c[0x0085:0x0088]!=bytes([0x02,0x1F,0x0E]):raise E("State14 prefix")
 tok(c,0x0088,0x7D,0x0400629D,"State=14")
 tok(c,0x0090,0x7B,0x040062A4,"TargetPlIdx case12/14")
 tok(c,0x0095,0x28,0x0600508C,"DecideRefereeDir case12/14")
 tok(c,0x009A,0x7D,0x040062A3,"PlDir case12/14")
 tok(c,0x00A0,0x7E,0x04006297,"RefAnmTbl case12/14")
 tok(c,0x00A7,0x7E,0x0400565B,"AnmOfsTbl_3Dir case12/14")
 tok(c,0x00AD,0x7B,0x040062A3,"PlDir table case12/14")
 tok(c,0x00B5,0x28,0x06005096,"ReqRefereeAnm case12/14")
 tok(c,0x00BB,0x7E,0x0400628B,"FoulWaitCnt")
 tok(c,0x00C1,0x7B,0x040062C3,"RefePrm foul")
 tok(c,0x00C6,0x7B,0x04000E72,"foulCount")
 tok(c,0x00CC,0x7D,0x040062B4,"FrameWait foul")
 if c[0x00D6:0x00D9]!=bytes([0x02,0x1F,0x0B]):raise E("State11 prefix")
 tok(c,0x00D9,0x7D,0x0400629D,"State=11")
 tok(c,0x00F4,0x28,0x06005096,"ReqRefereeAnm case11")
 tok(c,0x00FA,0x7E,0x0400628A,"OutWaitCnt")
 tok(c,0x0100,0x7B,0x040062C3,"RefePrm out")
 tok(c,0x0105,0x7B,0x04000E74,"outCount")
 tok(c,0x010B,0x7D,0x040062B4,"FrameWait out")
 if c[0x0115:0x0118]!=bytes([0x02,0x1F,0x0D]):raise E("State13 prefix")
 tok(c,0x0118,0x7D,0x0400629D,"State=13")
 tok(c,0x0133,0x28,0x06005096,"ReqRefereeAnm case13")
 tok(c,0x0139,0x7E,0x0400628B,"FoulWaitCnt case13")
 if c[0x0154:0x0157]!=bytes([0x02,0x1F,0x10]):raise E("State16 prefix")
 tok(c,0x0157,0x7D,0x0400629D,"State=16")
 if c[0x015C]!=0x06:raise E("player local case16")
 tok(c,0x015D,0x7B,0x04005FEE,"Player.Zone")
 tok(c,0x016A,0x7B,0x040062A4,"TargetPlIdx case16")
 tok(c,0x016F,0x28,0x0600508C,"DecideRefereeDir case16")
 tok(c,0x0174,0x7D,0x040062A3,"PlDir case16")
 tok(c,0x017A,0x7E,0x04006297,"RefAnmTbl case16")
 if c[0x017F:0x0182]!=bytes([0x1F,0x2F,0x7E]):raise E("raw47/2dir load")
 if struct.unpack_from("<I",c,0x0182)[0]!=0x0400565C:raise E("AnmOfsTbl_2Dir case16")
 tok(c,0x018F,0x28,0x06005096,"ReqRefereeAnm case16")
 if c[0x0199:0x019C]!=bytes([0x02,0x1F,0x0A]):raise E("State10 prefix")
 tok(c,0x019C,0x7D,0x0400629D,"State=10")
 tok(c,0x01A9,0x28,0x0600508C,"DecideRefereeDir case10")
 tok(c,0x01C9,0x28,0x06005096,"ReqRefereeAnm case10")
 if c[0x01CF:0x01D2]!=bytes([0x1F,0x32,0x7D]):raise E("FrameWait50")
 if struct.unpack_from("<I",c,0x01D2)[0]!=0x040062B4:raise E("FrameWait field case10")
 if c[0x01DB:0x01DE]!=bytes([0x02,0x1F,0x11]):raise E("State17 prefix")
 tok(c,0x01DE,0x7D,0x0400629D,"State=17")
 tok(c,0x01EB,0x28,0x0600508C,"DecideRefereeDir case17")
 if c[0x01FB:0x01FE]!=bytes([0x1F,0x2F,0x7E]):raise E("raw47/2dir case17")
 if struct.unpack_from("<I",c,0x01FE)[0]!=0x0400565C:raise E("AnmOfsTbl_2Dir case17")
 tok(c,0x020B,0x28,0x06005096,"ReqRefereeAnm case17")
 tok(c,0x0216,0x28,0x0600509D,"Start_HandlingDisturbing")
 if c[0x0220]!=0x2A:raise E("final ret")
 tok(cs["Move"],0x0053,0x28,0x0600509F,"FACT-0084 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Arrived"][2]},"raw_next_state_range":[9,18],"fact_0084_call_il":"0x0053"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_ARRIVED_DESTINATION: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_ARRIVED_DESTINATION: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
