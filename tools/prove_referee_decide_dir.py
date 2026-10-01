#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Dir":(0x00307384,107,"619774a8896b2e0f017a07bcca09e6a9a2c976f75c90f2f8d648669cfb7172a1"),
 "Arrived":(0x00308668,545,"ec45a72452fcbddd71df0a05d3c7b9a68df75fa36c1452a36638468a5e9db5e4")
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
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Dir"]
 tok(c,0x0000,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0005]!=0x03:raise E("pl_idx")
 tok(c,0x0006,0x6F,0x06005065,"PlayerMan.GetPlObj")
 if c[0x000B:0x000D]!=bytes([0x0A,0x06]):raise E("player local")
 tok(c,0x000D,0x28,0x0A00002A,"Player implicit")
 br(c,0x0012,0x3A,0x0019,"player true")
 if c[0x0017:0x0019]!=bytes([0x17,0x2A]):raise E("missing player raw1")
 if c[0x0019]!=0x06:raise E("player local vector")
 tok(c,0x001A,0x7B,0x04005FAA,"Player.PlPos")
 if c[0x001F]!=0x02:raise E("referee this")
 tok(c,0x0020,0x7B,0x040062A0,"Referee.PlPos")
 tok(c,0x0025,0x28,0x0A000049,"Vector3 subtraction")
 tok(c,0x002A,0x28,0x0A000089,"Vector2 implicit")
 if c[0x002F]!=0x0B:raise E("stloc1")
 if c[0x0030:0x0032]!=bytes([0x12,0x01]):raise E("ldloca.s1 x")
 tok(c,0x0032,0x7B,0x0A000059,"Vector2.x")
 f32(c,0x0037,0.0,"x zero")
 br(c,0x003C,0x42,0x0056,"x bgt.un")
 if c[0x0041:0x0043]!=bytes([0x12,0x01]):raise E("ldloca.s1 y left")
 tok(c,0x0043,0x7B,0x0A00005A,"Vector2.y left")
 f32(c,0x0048,0.0,"y left zero")
 br(c,0x004D,0x42,0x0054,"y left bgt.un")
 if c[0x0052:0x0056]!=bytes([0x17,0x2A,0x18,0x2A]):raise E("left returns 1/2")
 if c[0x0056:0x0058]!=bytes([0x12,0x01]):raise E("ldloca.s1 y right")
 tok(c,0x0058,0x7B,0x0A00005A,"Vector2.y right")
 f32(c,0x005D,0.0,"y right zero")
 br(c,0x0062,0x42,0x0069,"y right bgt.un")
 if c[0x0067:0x006B]!=bytes([0x1B,0x2A,0x1A,0x2A]):raise E("right returns 5/4")
 a=cs["Arrived"]
 for off in [0x0095,0x016F,0x01A9,0x01EB]:
  tok(a,off,0x28,0x0600508C,"FACT-0085 caller "+hex(off))
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Dir"][2]},"raw_return_set":[1,2,4,5],"fact_0085_calls":["0x0095","0x016F","0x01A9","0x01EB"]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_DECIDE_DIR: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_DECIDE_DIR: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
