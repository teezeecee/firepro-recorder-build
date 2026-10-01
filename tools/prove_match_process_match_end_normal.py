#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Leaf":(0x002A9904,261,"f204671841365e78a2dfef78bb7a34a0c483ee30ac13d388b9b28b22cd5f17e9"),"Caller":(0x00309428,156,"e71d1708191a0dc125367efbaa8adb8c280f8e1068cf6ae26ea320a98d482d8b")}
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
 tok(c,0x0000,0x7E,0x040061FA,"PlayerMan.inst winner")
 if c[0x0005]!=0x04:raise E("winner arg")
 tok(c,0x0006,0x6F,0x06005065,"GetPlObj winner")
 if c[0x000B:0x000D]!=bytes([0x0A,0x06]):raise E("winner local")
 tok(c,0x000D,0x28,0x0A00002A,"winner implicit")
 br(c,0x0012,0x3A,0x0018,"winner true")
 if c[0x0017]!=0x2A:raise E("winner false return")
 tok(c,0x0018,0x7E,0x040056FF,"MatchEvaluation.inst winner")
 tok(c,0x001D,0x7B,0x04005700,"PlResult winner")
 if c[0x0022:0x0025]!=bytes([0x04,0x9A,0x0B]):raise E("winner PlResult index")
 if c[0x0025:0x0027]!=bytes([0x07,0x16]):raise E("winner resultPosition zero")
 tok(c,0x0027,0x7D,0x040056CF,"resultPosition winner")
 if c[0x002C]!=0x06:raise E("winner controller")
 tok(c,0x002D,0x7B,0x0400602B,"plController")
 tok(c,0x0032,0x7B,0x04006115,"controller kind")
 if c[0x0037]!=0x18:raise E("kind raw2")
 br(c,0x0038,0x40,0x0048,"kind !=2")
 if c[0x003D]!=0x02:raise E("exitTimer this")
 i4(c,0x003E,900,"exitTimer 900")
 tok(c,0x0043,0x7D,0x04005743,"exitTimer")
 if c[0x0048:0x004A]!=bytes([0x16,0x0C]):raise E("loop index zero")
 br(c,0x004A,0x38,0x00EB,"initial loop branch")
 tok(c,0x004F,0x7E,0x040061FA,"PlayerMan.inst loop")
 if c[0x0054]!=0x08:raise E("loop index lookup")
 tok(c,0x0055,0x6F,0x06005065,"GetPlObj loop")
 if c[0x005A:0x005C]!=bytes([0x0D,0x09]):raise E("loop player local")
 tok(c,0x005C,0x28,0x0A00002A,"loop implicit")
 br(c,0x0061,0x3A,0x006B,"loop player true")
 br(c,0x0066,0x38,0x00E7,"null continue")
 if c[0x006B]!=0x09:raise E("sleep player")
 tok(c,0x006C,0x7B,0x04006057,"isSleep")
 br(c,0x0071,0x39,0x007B,"sleep zero")
 br(c,0x0076,0x38,0x00E7,"sleep continue")
 tok(c,0x007B,0x7E,0x040056FF,"MatchEvaluation.inst loop")
 tok(c,0x0080,0x7B,0x04005700,"PlResult loop")
 if c[0x0085:0x0089]!=bytes([0x08,0x9A,0x13,0x04]):raise E("loop PlResult[index]")
 if c[0x0089:0x008B]!=bytes([0x08,0x04]):raise E("index winner compare")
 br(c,0x008B,0x3B,0x00D5,"winner index")
 if c[0x0090]!=0x06:raise E("winner Group")
 tok(c,0x0091,0x7B,0x04005FF0,"winner Group field")
 if c[0x0096]!=0x09:raise E("loop Group")
 tok(c,0x0097,0x7B,0x04005FF0,"loop Group field")
 br(c,0x009C,0x40,0x00AE,"groups differ")
 if c[0x00A1:0x00A4]!=bytes([0x11,0x04,0x17]):raise E("same-group position1")
 tok(c,0x00A4,0x7D,0x040056CF,"resultPosition 1")
 br(c,0x00A9,0x38,0x00D5,"same-group join")
 if c[0x00AE]!=0x09:raise E("hasRight player")
 tok(c,0x00AF,0x7B,0x04006043,"hasRight")
 br(c,0x00B4,0x39,0x00CD,"hasRight false")
 if c[0x00B9:0x00BC]!=bytes([0x11,0x04,0x18]):raise E("position2 args")
 tok(c,0x00BC,0x7D,0x040056CF,"resultPosition 2")
 if c[0x00C1:0x00C3]!=bytes([0x09,0x17]):raise E("isLoseAndStop one")
 tok(c,0x00C3,0x7D,0x04006070,"isLoseAndStop")
 br(c,0x00C8,0x38,0x00D5,"position2 join")
 if c[0x00CD:0x00D0]!=bytes([0x11,0x04,0x19]):raise E("position3 args")
 tok(c,0x00D0,0x7D,0x040056CF,"resultPosition 3")
 if c[0x00D5:0x00D7]!=bytes([0x11,0x04]):raise E("finishTime result")
 tok(c,0x00D7,0x7B,0x040056D1,"finishTime")
 if c[0x00DC]!=0x02:raise E("matchTime this")
 tok(c,0x00DD,0x7B,0x0400573B,"matchTime")
 tok(c,0x00E2,0x6F,0x06004905,"MatchTime.Set")
 if c[0x00E7:0x00EB]!=bytes([0x08,0x17,0x58,0x0C]):raise E("loop increment")
 if c[0x00EB:0x00EE]!=bytes([0x08,0x1E,0x3F]):raise E("loop <8")
 if struct.unpack_from("<i",c,0x00EE)[0]!=(0x004F-0x00F2):raise E("loop target")
 if c[0x00F2:0x00F4]!=bytes([0x02,0x17]):raise E("isMatchEnd one")
 tok(c,0x00F4,0x7D,0x04005753,"isMatchEnd")
 tok(c,0x00F9,0x7E,0x040056FF,"MatchEvaluation.inst final")
 if c[0x00FE]!=0x03:raise E("match_result arg")
 tok(c,0x00FF,0x7D,0x04005701,"ResultType")
 if c[0x0104]!=0x2A:raise E("ret")
 tok(cs["Caller"],0x0096,0x6F,0x06004928,"FACT-0093 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"raw_scan":[0,7],"raw_result_positions":[0,1,2,3]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_MATCH_PROCESS_MATCH_END_NORMAL: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_MATCH_PROCESS_MATCH_END_NORMAL: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
