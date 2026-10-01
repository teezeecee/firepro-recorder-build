#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Scheduler":(0x00309E9C,160,"1a435c9d3f94c89836c5a175bee66f7a1fb84e4e7a7c8af9197108c533df1004"),
 "Entrance":(0x002AA570,822,"574be9a2193d91b436a4a241a5dee31bd03c08b32ca09d28dbdf4afd60990cde"),
 "Match":(0x002AA8B4,1152,"b6841694e03be5ca4c73e966a13802de9fe7339ab63540ffdf5edaee96ea9dfe")
}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Scheduler"]
 tok(c,0x0000,0x7E,0x0400576C,"MatchMain.inst")
 tok(c,0x0007,0x7B,0x0400629D,"State gate")
 if c[0x000C:0x000E]!=bytes([0x1F,0x16]):raise E("raw State 22")
 br(c,0x000E,0x40,0x001A,"State != 22")
 tok(c,0x0014,0x28,0x06005097,"FACT-0070 early UpdateRefereeAnm")
 if c[0x0019]!=0x2A:raise E("early return")
 tok(c,0x001C,0x7B,0x0400629D,"State copy source")
 tok(c,0x0021,0x7D,0x0400629E,"PrevState")
 seq=[(0x0027,0x0600507F),(0x002D,0x06005080),(0x0033,0x060050A3)]
 for off,t in seq:tok(c,off,0x28,t,"scheduler call "+hex(t))
 tok(c,0x0039,0x7B,0x04005753,"isMatchEnd")
 br(c,0x003E,0x3A,0x0049,"isMatchEnd skip ReturnWrestlers")
 tok(c,0x0044,0x28,0x060050AA,"ReturnWrestlers")
 for off,t in [(0x004A,0x060050AB),(0x0050,0x060050A2),(0x0056,0x06005089),(0x005C,0x060050A0),(0x0062,0x0600509E),(0x0068,0x0600508A),(0x006E,0x06005099),(0x0074,0x060050AC),(0x007A,0x060050A9),(0x0080,0x06005097)]:
  tok(c,off,0x28,t,"ordered call "+hex(t))
 tok(c,0x0086,0x7B,0x040062C8,"disturbedCnt gate")
 br(c,0x008C,0x3E,0x009F,"disturbedCnt <= 0")
 tok(c,0x0093,0x7B,0x040062C8,"disturbedCnt load")
 if c[0x0098:0x009A]!=bytes([0x17,0x59]):raise E("disturbedCnt -1")
 tok(c,0x009A,0x7D,0x040062C8,"disturbedCnt store")
 if c[0x009F]!=0x2A:raise E("ret")
 tok(cs["Entrance"],0x0021,0x6F,0x060050AF,"Update_EntranceScene caller")
 tok(cs["Match"],0x0051,0x6F,0x060050AF,"Update_Match caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Scheduler"][2]},"direct_callers":["0x06004935","0x06004936"]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_UPDATE_SCHEDULER: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_UPDATE_SCHEDULER: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
