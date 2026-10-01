#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Layer":(0x002A0A97,25,"706f9840af6e5fc17181d4522b1d7900ff500e0dd9c657c47a45849fa0a0eb45"),
 "Shake":(0x0030C001,8,"f8a8ac1e526882d2d8478bd371f6d9d6027b364f890e507fe69dfc7b9da02623"),
 "Vib":(0x002A10D6,25,"71a69e97e6e16dc6e78a660ef0833d3e5999bf892f194d77054a5c49003dba1c"),
 "Effect":(0x002A4AA4,152,"fc8982922fb7bba57f9f0052110e69463503c4f343c90fc030846e61e7a2e049")
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
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise ProofError(l)
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Layer"]
 if c[0:2]!=bytes([0x02,0x16]):raise ProofError("layer lower args")
 br(c,0x0002,0x3F,0x000F,"layer <0")
 if c[0x0007:0x000A]!=bytes([0x02,0x1F,0x09]):raise ProofError("layer upper args")
 br(c,0x000A,0x3F,0x0011,"layer <9")
 if c[0x000F:0x0011]!=bytes([0x16,0x2A]):raise ProofError("layer out return")
 tok(c,0x0011,0x7E,0x040055FD,"layerID table")
 if c[0x0016:0x0019]!=bytes([0x02,0x94,0x2A]):raise ProofError("layer table return")
 c=cs["Shake"]
 if c[0:2]!=bytes([0x02,0x03]):raise ProofError("shake args")
 tok(c,0x0002,0x7D,0x0400636E,"ShakeCnt")
 if c[0x0007]!=0x2A:raise ProofError("shake ret")
 c=cs["Vib"]
 if c[0]!=0x02:raise ProofError("vib this")
 f32(c,0x0001,0.05000000074505806,"vib factor")
 if c[0x0006:0x0008]!=bytes([0x03,0x5A]):raise ProofError("vib arg mul")
 tok(c,0x0008,0x7D,0x04005608,"VibPos")
 if c[0x000D]!=0x02:raise ProofError("vib this2")
 f32(c,0x000E,0.0,"VibVel zero")
 tok(c,0x0013,0x7D,0x04005607,"VibVel")
 if c[0x0018]!=0x2A:raise ProofError("vib ret")
 c=cs["Effect"]
 tok(c,0x005D,0x28,0x06004876,"FACT-0056 Layer caller")
 tok(c,0x0083,0x6F,0x060050E3,"FACT-0056 Shake caller")
 tok(c,0x0092,0x6F,0x06004884,"FACT-0056 Vib caller")
 return {"dll_sha256":got,"methods":{n:{"code_size":len(cs[n]),"code_sha256":M[n][2]} for n in ["Layer","Shake","Vib"]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_MINE_PRESENTATION_SUPPORT: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_MINE_PRESENTATION_SUPPORT: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
