#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Outer":(0x00308898,123,"a77f5e25b67af39e16a62e15a171465293dbae28e3851625a93c49f9ef820868"),
 "Inner":(0x00308920,1112,"8531aa20df597f7d7a37246779e58c39c7c7a2fdc6e34d4d38dcd1fd56f6f7e5"),
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
 c=cs["Outer"]
 tok(c,0x0000,0x7E,0x0400576C,"MatchMain.inst")
 if c[0x0005]!=0x0A:raise E("MatchMain local")
 if c[0x0006]!=0x02:raise E("this State")
 tok(c,0x0007,0x7B,0x0400629D,"State")
 if c[0x000C]!=0x1B:raise E("raw State 5")
 br(c,0x000D,0x3E,0x0013,"State <= 5")
 if c[0x0012]!=0x2A:raise E("State fail return")
 if c[0x0013]!=0x06:raise E("MatchMain local end")
 tok(c,0x0014,0x7B,0x04005753,"isMatchEnd")
 br(c,0x0019,0x39,0x001F,"isMatchEnd zero")
 if c[0x001E]!=0x2A:raise E("isMatchEnd return")
 if c[0x001F]!=0x06:raise E("MatchMain local round")
 tok(c,0x0020,0x7B,0x04005756,"isRoundEnd")
 br(c,0x0025,0x39,0x002B,"isRoundEnd zero")
 if c[0x002A]!=0x2A:raise E("isRoundEnd return")
 if c[0x002B:0x002D]!=bytes([0x16,0x0B]):raise E("index zero")
 br(c,0x002D,0x38,0x0073,"initial loop branch")
 tok(c,0x0032,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0037]!=0x07:raise E("loop index lookup")
 tok(c,0x0038,0x6F,0x06005065,"GetPlObj")
 if c[0x003D:0x003F]!=bytes([0x0C,0x08]):raise E("player local")
 tok(c,0x003F,0x28,0x0A00002A,"Player implicit")
 br(c,0x0044,0x3A,0x004E,"player true")
 br(c,0x0049,0x38,0x006F,"player false continue")
 if c[0x004E]!=0x08:raise E("player local sleep")
 tok(c,0x004F,0x7B,0x04006057,"Player.isSleep")
 br(c,0x0054,0x39,0x005E,"sleep zero")
 br(c,0x0059,0x38,0x006F,"sleep nonzero continue")
 if c[0x005E:0x0060]!=bytes([0x02,0x07]):raise E("inner args")
 tok(c,0x0060,0x28,0x060050A1,"inner CheckStartRefereeing")
 br(c,0x0065,0x39,0x006F,"inner false continue")
 br(c,0x006A,0x38,0x007A,"inner true return")
 if c[0x006F:0x0073]!=bytes([0x07,0x17,0x58,0x0B]):raise E("index increment")
 if c[0x0073:0x0076]!=bytes([0x07,0x1E,0x3F]):raise E("index < 8")
 if struct.unpack_from("<i",c,0x0076)[0]!=(0x0032-0x007A):raise E("loop target")
 if c[0x007A]!=0x2A:raise E("final return")
 tok(cs["Scheduler"],0x005C,0x28,0x060050A0,"FACT-0074 direct caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Outer"][2]},"scan_indices":[0,7],"inner_token":"0x060050A1","direct_callers":1}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_CHECK_START_SCANNER: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_CHECK_START_SCANNER: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
