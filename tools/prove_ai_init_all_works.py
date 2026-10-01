#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
"InitAllWorks":(0x002F5DF0,213,"f79b47e5840d3c2948b9ce1a4af92f400b37f9fa52d613a9fb2a5b91674edeee"),
"Init":(0x002F5ADC,775,"7a738543d0ba6f0c0fbd5a6121ba72aceb6c2c2ec1477b08f3ede6390a557e30")}
ZERO=[(0x0002,0x04006118),(0x0009,0x04006117),(0x0010,0x0400614B),(0x0017,0x0400614D),(0x001E,0x0400614C),
(0x0025,0x04006153),(0x002C,0x0400614E),(0x003A,0x04006150),(0x0041,0x04006154),(0x0048,0x04006155),
(0x004F,0x04006156),(0x0056,0x04006157),(0x005D,0x04006158),(0x0064,0x0400615C),(0x006B,0x0400615F),
(0x0072,0x04006166),(0x0079,0x04006169),(0x009B,0x0400616A),(0x00A2,0x0400616B),(0x00A9,0x0400616C),(0x00B0,0x0400616D)]
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
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["InitAllWorks"]
 for off,t in ZERO:
  if c[off-2:off]!=bytes([0x02,0x16]):raise ProofError("zero args "+hex(off))
  tok(c,off,0x7D,t,"zero field "+hex(t))
 for off,t in [(0x0033,0x0400614F),(0x0080,0x04006151),(0x00CF,0x04006171)]:
  if c[off-2:off]!=bytes([0x02,0x15]):raise ProofError("minus-one args "+hex(off))
  tok(c,off,0x7D,t,"minus-one field "+hex(t))
 i4(c,0x0087,216000,"shared timer value")
 tok(c,0x008E,0x7D,0x04006168,"notDisturbTime_AllSecond")
 tok(c,0x0094,0x7D,0x04006167,"notDisturbTime")
 tok(c,0x00B6,0x28,0x06004FD8,"Reset_HungUpCheck")
 tok(c,0x00BC,0x28,0x06005007,"ResetCheckedPriAct")
 if c[0x00C1]!=0x03:raise ProofError("create_init arg")
 br(c,0x00C2,0x3A,0x00CD,"create_init true skip")
 tok(c,0x00C8,0x28,0x06004FFE,"CalcTouchTime false path")
 if c[0x00D4]!=0x2A:raise ProofError("ret")
 init=cs["Init"]
 if init[0:2]!=bytes([0x02,0x17]):raise ProofError("Init true caller args")
 tok(init,0x0002,0x28,0x06004F9A,"InitAllWorks caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["InitAllWorks"][2]},"timer_value":216000}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_AI_INIT_ALL_WORKS: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_AI_INIT_ALL_WORKS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
