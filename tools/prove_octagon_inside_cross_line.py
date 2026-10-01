#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Cross":(0x0030CF88,538,"342c92172a4c47371d07312bf9b8d7bec1b5d2cd2cbe9019255e8282ee26b59f"),"Auto":(0x002E08B8,712,"6bd624830f79c47cf800b28715a0f2628127003f9bf80484b8da7793ecaeb56d")}
TARGETS=[0x0050,0x00B4,0x0117,0x017C]
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
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise ProofError(l)
def switch_targets(c,o):
 if c[o]!=0x45:raise ProofError("switch")
 n=struct.unpack_from("<I",c,o+1)[0];base=o+5+4*n
 return [base+struct.unpack_from("<i",c,o+5+4*i)[0] for i in range(n)]
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Cross"]
 tok(c,0x0002,0x28,0x0A00008B,"Vector2.zero")
 f32(c,0x001A,10.666666030883789,"raw scalar")
 tok(c,0x0029,0x73,0x0A000088,"start Vector2 ctor")
 if switch_targets(c,0x0036)!=TARGETS:raise ProofError("pb2 switch targets")
 # Case 2 fields / vector addition
 tok(c,0x0066,0x73,0x0A000088,"case2 offset ctor");tok(c,0x006B,0x28,0x0A00008E,"case2 addition")
 for off,t in [(0x007D,0x0400647F),(0x0083,0x04006484),(0x009A,0x04006480),(0x00A0,0x04006483),
              (0x00E0,0x04006481),(0x00E6,0x04006483),(0x00FD,0x04006482),(0x0103,0x04006484),
              (0x0145,0x04006480),(0x014B,0x04006486),(0x0162,0x0400647F),(0x0168,0x04006485),
              (0x01A9,0x04006482),(0x01AF,0x04006485),(0x01C6,0x04006481),(0x01CC,0x04006486)]:
  tok(c,off,0x7B,t,"octagon field "+hex(off))
 if c[0x01E0:0x01E2]!=bytes([0x16,0x2A]):raise ProofError("default false return")
 tok(c,0x0214,0x28,0x06004A92,"IsIntersect_Segment")
 if c[0x0219]!=0x2A:raise ProofError("return")
 tok(cs["Auto"],0x0162,0x28,0x060050FB,"FACT-0050 caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Cross"][2]},"switch_targets":[hex(x) for x in TARGETS]}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_OCTAGON_INSIDE_CROSS_LINE: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_OCTAGON_INSIDE_CROSS_LINE: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
