#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x00309544,168,"14d88238c271a882dd9fe1c4d3a0fdd732d43a830be6728478f50747326aab9f"),
 "Scheduler":(0x00309E9C,160,"1a435c9d3f94c89836c5a175bee66f7a1fb84e4e7a7c8af9197108c533df1004")
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
 if c[0x0006]!=0x02:raise E("this standby")
 tok(c,0x0007,0x28,0x060050A8,"CheckStandByWrestler")
 br(c,0x000C,0x39,0x0012,"standby false continue")
 if c[0x0011]!=0x2A:raise E("standby true return")
 if c[0x0012]!=0x06:raise E("MatchMain local end")
 tok(c,0x0013,0x7B,0x04005753,"isMatchEnd")
 br(c,0x0018,0x39,0x001E,"match end zero")
 if c[0x001D]!=0x2A:raise E("match end return")
 if c[0x001E]!=0x06:raise E("MatchMain local round")
 tok(c,0x001F,0x7B,0x04005756,"isRoundEnd")
 br(c,0x0024,0x39,0x002A,"round end zero")
 if c[0x0029]!=0x2A:raise E("round end return")
 tok(c,0x002A,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x002F,0x7B,0x04002AD2,"MatchSetting")
 if c[0x0034]!=0x0B:raise E("MatchSetting local")
 tok(c,0x0035,0x7E,0x040061FA,"PlayerMan.inst")
 tok(c,0x003A,0x6F,0x0600506C,"GetWrestlerNum_HasRight")
 if c[0x003F:0x0041]!=bytes([0x0C,0x08]):raise E("count local")
 br(c,0x0041,0x3A,0x0057,"nonzero count")
 if c[0x0046:0x0048]!=bytes([0x06,0x02]):raise E("draw args")
 tok(c,0x0048,0x7B,0x040062D0,"isTwoDownWithExplosion")
 tok(c,0x004D,0x6F,0x0600492D,"ProcessMatchEnd_Draw")
 br(c,0x0052,0x38,0x00A7,"draw end")
 if c[0x0057]!=0x07:raise E("setting local battle")
 tok(c,0x0058,0x7B,0x040057D3,"BattleRoyalKind")
 br(c,0x005D,0x39,0x006D,"battle zero")
 if c[0x0062]!=0x02:raise E("battle this")
 tok(c,0x0063,0x28,0x060050A5,"CheckMatchEnd_BattleRoyal")
 br(c,0x0068,0x38,0x00A7,"battle end")
 if c[0x006D]!=0x07:raise E("setting local victory")
 tok(c,0x006E,0x7B,0x040057D0,"VictoryCondition")
 if c[0x0073]!=0x1A:raise E("raw victory 4")
 br(c,0x0074,0x40,0x0084,"victory !=4")
 if c[0x0079]!=0x02:raise E("escape this")
 tok(c,0x007A,0x28,0x060050A4,"CheckMatchEnd_EscapedFromCage")
 br(c,0x007F,0x38,0x00A7,"escape end")
 if c[0x0084]!=0x07:raise E("setting tornado")
 tok(c,0x0085,0x7B,0x040057F6,"isTornadoBattle")
 br(c,0x008A,0x39,0x009A,"tornado zero")
 if c[0x008F]!=0x02:raise E("tornado this")
 tok(c,0x0090,0x28,0x060050A6,"CheckMatchEnd_Tornado")
 br(c,0x0095,0x38,0x00A7,"tornado end")
 if c[0x009A:0x009C]!=bytes([0x08,0x17]):raise E("count==1")
 br(c,0x009C,0x40,0x00A7,"count !=1")
 if c[0x00A1]!=0x02:raise E("normal this")
 tok(c,0x00A2,0x28,0x060050A7,"ProcesskMatchEnd_Normal")
 if c[0x00A7]!=0x2A:raise E("ret")
 tok(cs["Scheduler"],0x007A,0x28,0x060050A9,"FACT-0074 direct caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"direct_callers":1,"raw_victory_value":4}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_CHECK_MATCH_END: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_CHECK_MATCH_END: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
