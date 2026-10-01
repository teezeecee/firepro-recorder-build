#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00305AA0
SIZE=244
BODY_SHA="e49118b8c0107b96e5bcca09a2cd24853191f05c685c858415a176cac7ba3bc2"
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
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise E(l)
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();c=code(pe,secs(pe),RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=BODY_SHA:raise E("InitRound body")
 tok(c,0x0000,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x0005,0x7B,0x04002AD2,"MatchSetting")
 if c[0x000A]!=0x0A:raise E("stloc.0")
 if 0x03 in c:raise E("unexpected ldarg.1 / rd load")
 tok(c,0x000C,0x7B,0x040057D3,"BattleRoyalKind #1")
 br(c,0x0011,0x39,0x0067,"BattleRoyalKind zero branch")
 tok(c,0x0017,0x7C,0x040062A0,"PlPos x path1");f32(c,0x001C,0.0,"x path1");tok(c,0x0021,0x7D,0x0A000009,"Vector3.x #1")
 tok(c,0x0027,0x7C,0x040062A0,"PlPos y path1");f32(c,0x002C,0.0,"y path1");tok(c,0x0031,0x7D,0x0A00000A,"Vector3.y #1")
 tok(c,0x0037,0x7B,0x040057D3,"BattleRoyalKind #2")
 if c[0x003C]!=0x1A:raise E("raw kind 4")
 br(c,0x003D,0x40,0x0062,"kind != 4")
 tok(c,0x0043,0x7C,0x040062A0,"PlPos x kind4");f32(c,0x0048,0.0,"x kind4");tok(c,0x004D,0x7D,0x0A000009,"Vector3.x #2")
 tok(c,0x0053,0x7C,0x040062A0,"PlPos y kind4");f32(c,0x0058,1.0,"y kind4");tok(c,0x005D,0x7D,0x0A00000A,"Vector3.y #2")
 br(c,0x0062,0x38,0x0087,"join xy")
 tok(c,0x0068,0x7C,0x040062A0,"PlPos x kind0");f32(c,0x006D,0.0,"x kind0");tok(c,0x0072,0x7D,0x0A000009,"Vector3.x #3")
 tok(c,0x0078,0x7C,0x040062A0,"PlPos y kind0");f32(c,0x007D,1.0,"y kind0");tok(c,0x0082,0x7D,0x0A00000A,"Vector3.y #3")
 tok(c,0x0088,0x7B,0x040057D3,"BattleRoyalKind request gate")
 br(c,0x008D,0x3A,0x00B5,"nonzero kind alternate")
 tok(c,0x0093,0x7B,0x040057E7,"isFastForwardMatch")
 br(c,0x0098,0x3A,0x00B5,"fast-forward alternate")
 if c[0x009D:0x00A0]!=bytes([0x02,0x1F,0x16]):raise E("State 22 prefix")
 tok(c,0x00A0,0x7D,0x0400629D,"State 22")
 if c[0x00A5]!=0x02:raise E("this request1106")
 i4(c,0x00A6,1106,"raw 1106")
 tok(c,0x00AB,0x28,0x06005096,"FACT-0068 ReqRefereeAnm 1106")
 br(c,0x00B0,0x38,0x00CE,"first branch join")
 if c[0x00B5:0x00B8]!=bytes([0x02,0x1F,0x13]):raise E("State 19 prefix")
 tok(c,0x00B8,0x7D,0x0400629D,"State 19")
 if c[0x00BD]!=0x02:raise E("this request1121")
 i4(c,0x00BE,1121,"raw 1121")
 tok(c,0x00C3,0x28,0x06005096,"FACT-0068 ReqRefereeAnm 1121")
 if c[0x00C8]!=0x02:raise E("this UpdateRefereeAnm")
 tok(c,0x00C9,0x28,0x06005097,"UpdateRefereeAnm")
 tok(c,0x00CF,0x7C,0x040062A0,"PlPos z");f32(c,0x00D4,1.0,"z one");tok(c,0x00D9,0x7D,0x0A000056,"Vector3.z")
 if c[0x00DE:0x00E0]!=bytes([0x02,0x16]):raise E("Counter zero prefix")
 tok(c,0x00E0,0x7D,0x040062C4,"Counter")
 if c[0x00E5:0x00E7]!=bytes([0x02,0x15]):raise E("winner -1 prefix")
 tok(c,0x00E7,0x7D,0x040062C5,"plIdx_FirstWiner")
 if c[0x00EC:0x00EE]!=bytes([0x02,0x16]):raise E("stand timer zero prefix")
 tok(c,0x00EE,0x7D,0x040062A7,"standPoseTimer")
 if c[0x00F3]!=0x2A:raise E("ret")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":BODY_SHA},"rd_loaded":False,"raw_states":[22,19],"raw_requests":[1106,1121]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_INIT_ROUND: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_INIT_ROUND: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
