#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Area":(0x002B03A1,18,"654ba7cc9e57f9d89980c22e809e524ea356d0b765da69858346bf5f552f101e"),"Core":(0x0030C1AC,44,"9e30d379778702383767528e435f4f3286a8750330a3c347070a0bd6b2d7f040"),"Wrap":(0x0030C1D9,26,"176f302c0fcf51b200743023b8c7ca7028e80575b1fb3de87efd6d6bddf130d6"),"Auto":(0x002E08B8,712,"6bd624830f79c47cf800b28715a0f2628127003f9bf80484b8da7793ecaeb56d")}
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
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Area"]
 if c[0:2]!=bytes([0x02,0x18]):raise ProofError("area raw2")
 br(c,0x0002,0x3B,0x000E,"area2 true")
 if c[0x0007:0x0009]!=bytes([0x02,0x19]):raise ProofError("area raw3")
 br(c,0x0009,0x40,0x0010,"area3/other")
 if c[0x000E:0x0012]!=bytes([0x17,0x2A,0x16,0x2A]):raise ProofError("area returns")
 c=cs["Core"]
 tok(c,0x0002,0x7B,0x0400648D,"y2")
 br(c,0x0007,0x44,0x001C,"y blt.un")
 tok(c,0x000E,0x7B,0x0400648A,"x2 upper")
 br(c,0x0013,0x42,0x001A,"x bgt.un upper")
 if c[0x0018:0x001C]!=bytes([0x18,0x2A,0x19,0x2A]):raise ProofError("upper returns2/3")
 tok(c,0x001E,0x7B,0x0400648A,"x2 lower")
 br(c,0x0023,0x42,0x002A,"x bgt.un lower")
 if c[0x0028:0x002C]!=bytes([0x1A,0x2A,0x1B,0x2A]):raise ProofError("lower returns4/5")
 c=cs["Wrap"]
 tok(c,0x0001,0x7B,0x04006373,"around ring field")
 tok(c,0x0008,0x7B,0x0A000059,"p.x")
 tok(c,0x000F,0x7B,0x0A00005A,"p.y")
 tok(c,0x0014,0x28,0x060050E8,"core call")
 c=cs["Auto"]
 tok(c,0x0062,0x6F,0x060050E9,"FACT-0050 wrapper caller")
 for off in [0x0095,0x00B8,0x00F0,0x0113]:tok(c,off,0x28,0x06004961,"FACT-0050 area caller")
 return {"dll_sha256":got,"methods":{k:{"code_size":len(cs[k]),"code_sha256":M[k][2]} for k in ["Area","Core","Wrap"]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_AUTORUN_GEOMETRY_CLASSIFIERS: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_AUTORUN_GEOMETRY_CLASSIFIERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
