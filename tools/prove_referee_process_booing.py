#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x00308FB4,90,"b7e8964816ea334e17fdf26aeb44a9789251e264d1bcc2eedc1fbd0fcc3ea42d"),
 "Scheduler":(0x00309E9C,160,"1a435c9d3f94c89836c5a175bee66f7a1fb84e4e7a7c8af9197108c533df1004")
}
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
 tok(c,0x0000,0x7E,0x0400576C,"MatchMain.inst")
 if c[0x0005]!=0x0A or c[0x0006]!=0x06:raise E("local")
 tok(c,0x0007,0x7B,0x04005753,"isMatchEnd")
 br(c,0x000C,0x39,0x0012,"match not ended")
 if c[0x0011]!=0x2A:raise E("match-end return")
 if c[0x0012:0x0014]!=bytes([0x06,0x25]):raise E("increment receiver dup")
 tok(c,0x0014,0x7B,0x04005739,"BooingCnt read #1")
 if c[0x0019:0x001C]!=bytes([0x17,0x58,0x7D]):raise E("increment")
 if struct.unpack_from("<I",c,0x001C)[0]!=0x04005739:raise E("BooingCnt write #1")
 if c[0x0020]!=0x06:raise E("counter receiver")
 tok(c,0x0021,0x7B,0x04005739,"BooingCnt read #2")
 i4(c,0x0026,4096,"raw 4096")
 br(c,0x002B,0x40,0x0059,"counter inequality return")
 tok(c,0x0030,0x7E,0x040054C9,"Audience.inst #1")
 if c[0x0035:0x0038]!=bytes([0x1F,0x09,0x16]):raise E("PlayCheerVoice raw args")
 tok(c,0x0038,0x6F,0x060047D9,"Audience.PlayCheerVoice")
 if c[0x003D:0x003F]!=bytes([0x06,0x25]):raise E("subtract receiver dup")
 tok(c,0x003F,0x7B,0x04005739,"BooingCnt read #3")
 i4(c,0x0044,128,"raw 128")
 if c[0x0049:0x004B]!=bytes([0x59,0x7D]):raise E("subtract/store")
 if struct.unpack_from("<I",c,0x004B)[0]!=0x04005739:raise E("BooingCnt write #2")
 tok(c,0x004F,0x7E,0x040054C9,"Audience.inst #2")
 tok(c,0x0054,0x6F,0x060047D7,"Audience.TensionDown")
 if c[0x0059]!=0x2A:raise E("ret")
 tok(cs["Scheduler"],0x0033,0x28,0x060050A3,"FACT-0074 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"raw_trigger":4096,"raw_subtract":128}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_PROCESS_BOOING: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_PROCESS_BOOING: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
