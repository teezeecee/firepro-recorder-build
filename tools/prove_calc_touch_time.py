#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
"CalcTouchTime":(0x002FC064,129,"47a7f7261543bcf1382b1f1095a756cf101300461f48a08ca1e06c7ac5288589"),
"InitAllWorks":(0x002F5DF0,213,"f79b47e5840d3c2948b9ce1a4af92f400b37f9fa52d613a9fb2a5b91674edeee"),
"UpdatePlayer":(0x002F4308,0,None)}
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
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe)
 c=code(pe,ss,M["CalcTouchTime"][0])
 if len(c)!=M["CalcTouchTime"][1] or hashlib.sha256(c).hexdigest()!=M["CalcTouchTime"][2]:raise ProofError("CalcTouchTime body")
 for off,t in [(0x0000,0x04000D38),(0x0005,0x04000D3C),(0x000B,0x04000D38),(0x0010,0x04000D3D),(0x0016,0x04000D38),(0x001B,0x04000D3E)]:
  tok(c,off,0x7E if off in (0x0000,0x000B,0x0016) else 0x7B,t,"COMLevel field "+hex(off))
 tok(c,0x0022,0x7B,0x0400614A,"PlObj #1")
 tok(c,0x0028,0x28,0x0A000006,"null equality")
 br(c,0x002D,0x39,0x0033,"PlObj nonnull")
 tok(c,0x0034,0x7B,0x0400614A,"PlObj #2")
 tok(c,0x0039,0x7B,0x04005FB3,"WresParam #1")
 br(c,0x003E,0x3A,0x0044,"WresParam nonnull")
 tok(c,0x0045,0x7B,0x0400614A,"PlObj #3")
 tok(c,0x004A,0x7B,0x04005FB3,"WresParam #2")
 tok(c,0x004F,0x7B,0x040010AA,"aiParam")
 tok(c,0x005A,0x28,0x0600497B,"MatchRandom Range")
 tok(c,0x0065,0x7B,0x04000D2E,"touchCond")
 if c[0x0062:0x0064]!=bytes([0x1F,0x64]):raise ProofError("raw100")
 if c[0x0078:0x007A]!=bytes([0x1F,0x1E]):raise ProofError("raw30")
 tok(c,0x007B,0x7D,0x04006170,"touchFrm")
 if c[0x0080]!=0x2A:raise ProofError("ret")
 init=code(pe,ss,M["InitAllWorks"][0])
 tok(init,0x00C8,0x28,0x06004FFE,"FACT-0045 caller")
 up=code(pe,ss,0x002F4308)
 tok(up,0x0034,0x6F,0x06004FFE,"UpdatePlayer caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["CalcTouchTime"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_CALC_TOUCH_TIME: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_CALC_TOUCH_TIME: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
