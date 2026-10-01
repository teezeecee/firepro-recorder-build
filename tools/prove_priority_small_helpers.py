#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "GetDamageLevel_LMH":(0x002F5ED4,49,"9c943eda48fd9f9c76271366324f22095426c06b0eecbb77d37e0cc945dde6c3"),
 "Reset_HungUpCheck":(0x002F91A0,55,"9bea2fa5e79dc6e2c45acd5a83161a0ce0bec614c28ca0c2f0e63037bb0b2e01"),
 "ProcessPriorityAct":(0x002FD31C,431,"0db6da9710767a5629dec05b3a7521e0aa1cb83f55d6332a648e89fa5917afc1")
}
class ProofError(RuntimeError):pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1024*1024),b""):h.update(x)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise ProofError("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise ProofError("RVA unmapped")
 fb=pe[o]
 if fb&3==2:h=1;n=fb>>2
 elif fb&3==3:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 else:raise ProofError("bad IL header")
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
  cs[n]=c
 c=cs["GetDamageLevel_LMH"]
 tok(c,0x0001,0x28,0x06004975,"GetParamRate")
 tok(c,0x0008,0x7E,0x04000D38,"COMLevelDataManager.inst #1")
 tok(c,0x000D,0x7B,0x04000D3B,"damageLevelThreshold_LMH #1")
 tok(c,0x001C,0x7E,0x04000D38,"COMLevelDataManager.inst #2")
 tok(c,0x0021,0x7B,0x04000D3B,"damageLevelThreshold_LMH #2")
 br(c,0x0014,0x44,0x001B,"threshold0 blt.un")
 br(c,0x0028,0x44,0x002F,"threshold1 blt.un")
 if c[0x0012:0x0014]!=bytes([0x16,0x98]):raise ProofError("threshold index0")
 if c[0x0019:0x001B]!=bytes([0x16,0x2A]):raise ProofError("raw return0")
 if c[0x0026:0x0028]!=bytes([0x17,0x98]):raise ProofError("threshold index1")
 if c[0x002D:0x0031]!=bytes([0x17,0x2A,0x18,0x2A]):raise ProofError("raw returns1/2")
 c=cs["Reset_HungUpCheck"]
 tok(c,0x0002,0x7D,0x0400615A,"MoveCheckPosPtr")
 tok(c,0x0009,0x7D,0x0400615B,"MoveCheckPosRecordNum")
 tok(c,0x0016,0x7B,0x04006159,"MoveCheckPosBuf")
 tok(c,0x001C,0x8F,0x0100000C,"Vector2 element")
 tok(c,0x0021,0x28,0x0A00008B,"Vector2.get_zero")
 tok(c,0x0026,0x81,0x0100000C,"stobj Vector2")
 br(c,0x0010,0x38,0x002F,"loop entry")
 br(c,0x0031,0x3F,0x0015,"index<8")
 if c[0:2]!=bytes([0x02,0x16]) or c[7:9]!=bytes([0x02,0x16]):raise ProofError("counter zero stores")
 if c[0x000E:0x0010]!=bytes([0x16,0x0A]):raise ProofError("index init")
 if c[0x002B:0x002F]!=bytes([0x06,0x17,0x58,0x0A]):raise ProofError("index increment")
 if c[0x002F:0x0031]!=bytes([0x06,0x1E]) or c[0x0036]!=0x2A:raise ProofError("loop bound/ret")
 p=cs["ProcessPriorityAct"]
 tok(p,0x00E3,0x28,0x06004F9B,"ProcessPriorityAct GetDamageLevel")
 tok(p,0x0190,0x28,0x06004FD8,"ProcessPriorityAct Reset")
 return {"dll_sha256":got,"methods":{
  "GetDamageLevel_LMH":{"code_size":len(cs["GetDamageLevel_LMH"]),"code_sha256":M["GetDamageLevel_LMH"][2]},
  "Reset_HungUpCheck":{"code_size":len(cs["Reset_HungUpCheck"]),"code_sha256":M["Reset_HungUpCheck"][2]}}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_PRIORITY_SMALL_HELPERS: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_PRIORITY_SMALL_HELPERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
