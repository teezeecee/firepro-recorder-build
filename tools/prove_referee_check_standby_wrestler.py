#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x003094D0,103,"ee9e9c47f5d28bf25f68a8af0c22b9a0f794b042d30cbdc9dbf23ab310a3964d"),
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
 tok(c,0x0000,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x0005,0x7B,0x04002AD2,"MatchSetting")
 if c[0x000A:0x000C]!=bytes([0x0A,0x06]):raise E("setting local")
 tok(c,0x000C,0x7B,0x040057D3,"BattleRoyalKind")
 if c[0x0011]!=0x1A:raise E("raw4")
 br(c,0x0012,0x3B,0x0019,"BattleRoyalKind==4")
 if c[0x0017:0x0019]!=bytes([0x16,0x2A]):raise E("nonmatching false")
 if c[0x0019:0x001B]!=bytes([0x16,0x0B]):raise E("index zero")
 br(c,0x001B,0x38,0x005E,"initial loop branch")
 tok(c,0x0020,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0025]!=0x07:raise E("index lookup")
 tok(c,0x0026,0x6F,0x06005065,"GetPlObj")
 if c[0x002B:0x002D]!=bytes([0x0C,0x08]):raise E("player local")
 tok(c,0x002D,0x28,0x0A00002A,"Player implicit")
 br(c,0x0032,0x3A,0x003C,"player true")
 br(c,0x0037,0x38,0x005A,"player false continue")
 if c[0x003C]!=0x08:raise E("player sleep")
 tok(c,0x003D,0x7B,0x04006057,"isSleep")
 br(c,0x0042,0x39,0x004C,"sleep zero")
 br(c,0x0047,0x38,0x005A,"sleep nonzero continue")
 if c[0x004C]!=0x08:raise E("player appear")
 tok(c,0x004D,0x7B,0x04006035,"royalRambleAppearTime")
 if c[0x0052]!=0x15:raise E("raw -1")
 br(c,0x0053,0x3B,0x005A,"appear == -1 continue")
 if c[0x0058:0x005A]!=bytes([0x17,0x2A]):raise E("true return")
 if c[0x005A:0x005E]!=bytes([0x07,0x17,0x58,0x0B]):raise E("index increment")
 if c[0x005E:0x0061]!=bytes([0x07,0x1E,0x3F]):raise E("index <8")
 if struct.unpack_from("<i",c,0x0061)[0]!=(0x0020-0x0065):raise E("loop target")
 if c[0x0065:0x0067]!=bytes([0x16,0x2A]):raise E("exhaustion false")
 tok(cs["Caller"],0x0007,0x28,0x060050A8,"FACT-0091 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"raw_battle_royal_kind":4,"scan_indices":[0,7]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_CHECK_STANDBY_WRESTLER: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_CHECK_STANDBY_WRESTLER: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
