#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Move":(0x00308600,89,"58c6b30e276aa4ab2b5a5e4116f2f309ebb362cf4a6cb17d52245a744bd6fae1"),"Reached":(0x00307334,68,"ead82943535ec77fed4deda04c5e7adf102ba54ee322c82072b58762c619957b"),"Scheduler":(0x00309E9C,160,"1a435c9d3f94c89836c5a175bee66f7a1fb84e4e7a7c8af9197108c533df1004")}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
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
def f32bits(c,o,bits,l):
 if c[o]!=0x22 or struct.unpack_from("<I",c,o+1)[0]!=bits:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Move"]
 tok(c,0x0001,0x7B,0x0400629D,"State")
 if c[0x0006]!=0x1E:raise E("raw State 8")
 br(c,0x0007,0x3B,0x000D,"State == 8")
 if c[0x000C]!=0x2A:raise E("state fail ret")
 tok(c,0x000E,0x7C,0x040062A0,"PlPos x address");tok(c,0x0014,0x7B,0x0A000009,"PlPos.x")
 tok(c,0x001A,0x7C,0x040062CB,"MoveVel x address");tok(c,0x001F,0x7B,0x0A000059,"MoveVel.x")
 tok(c,0x0025,0x7D,0x0A000009,"PlPos.x write")
 tok(c,0x002B,0x7C,0x040062A0,"PlPos y address");tok(c,0x0031,0x7B,0x0A00000A,"PlPos.y")
 tok(c,0x0037,0x7C,0x040062CB,"MoveVel y address");tok(c,0x003C,0x7B,0x0A00005A,"MoveVel.y")
 tok(c,0x0042,0x7D,0x0A00000A,"PlPos.y write")
 tok(c,0x0048,0x28,0x0600508B,"IsReachedDestination");br(c,0x004D,0x39,0x0058,"not reached")
 tok(c,0x0053,0x28,0x0600509F,"Process_ArrivedDestination")
 if c[0x0058]!=0x2A:raise E("move ret")
 c=cs["Reached"]
 tok(c,0x0001,0x7B,0x040062CA,"DestPos");tok(c,0x0007,0x7B,0x040062A0,"PlPos")
 tok(c,0x000C,0x28,0x0A000089,"implicit PlPos");tok(c,0x0011,0x28,0x0A000100,"subtract")
 tok(c,0x0019,0x7B,0x040062CB,"MoveVel");tok(c,0x001E,0x28,0x0A0001AD,"Dot")
 f32bits(c,0x0023,0x00000000,"dot zero");br(c,0x0028,0x42,0x002F,"dot bgt.un")
 if c[0x002D:0x002F]!=bytes([0x17,0x2A]):raise E("dot true return")
 tok(c,0x0031,0x28,0x0A000091,"magnitude")
 f32bits(c,0x0036,0x3D7FFFFF,"magnitude threshold");br(c,0x003B,0x42,0x0042,"magnitude bgt.un")
 if c[0x0040:0x0044]!=bytes([0x17,0x2A,0x16,0x2A]):raise E("magnitude returns")
 tok(cs["Scheduler"],0x0062,0x28,0x0600509E,"FACT-0074 caller")
 return {"dll_sha256":DLL_SHA,"methods":{"Move":M["Move"][2],"Reached":M["Reached"][2]},"state":8,"threshold_bits":"0x3D7FFFFF"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_MOVE_DESTINATION: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_MOVE_DESTINATION: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
