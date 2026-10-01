#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Leaf":(0x00306394,100,"fba8e1eb077d2800274abf6f40345ed6768347f753aedaf9ccb023b2a24ea530"),"Scheduler":(0x00309E9C,160,"1a435c9d3f94c89836c5a175bee66f7a1fb84e4e7a7c8af9197108c533df1004")}
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 tok(c,0x0001,0x7B,0x0400629D,"State")
 if c[0x0006:0x0008]!=bytes([0x1F,0x13]):raise E("raw State 19")
 br(c,0x0008,0x3B,0x000E,"State == 19")
 if c[0x000D]!=0x2A:raise E("state fail return")
 tok(c,0x000F,0x7B,0x040062B0,"CurrentSkill gate")
 br(c,0x0014,0x3A,0x001A,"CurrentSkill non-null")
 if c[0x0019]!=0x2A:raise E("skill fail return")
 tok(c,0x001B,0x7B,0x040062B0,"CurrentSkill data")
 tok(c,0x0020,0x7B,0x04007C7A,"anmData")
 tok(c,0x0026,0x7B,0x040062B1,"CurrentAnmIdx")
 if c[0x002B:0x002D]!=bytes([0x9A,0x0A]):raise E("anmData element local")
 tok(c,0x002E,0x7B,0x040062B3,"currentFormIdx")
 tok(c,0x0034,0x7B,0x04007C93,"formNum")
 if c[0x0039:0x003D]!=bytes([0x1C,0x59,0x17,0x59]):raise E("formNum - 6 - 1")
 br(c,0x003D,0x40,0x0063,"form index inequality")
 tok(c,0x0043,0x7B,0x040062B2,"FormDispDuration")
 br(c,0x0048,0x3A,0x0063,"duration nonzero")
 tok(c,0x004D,0x7E,0x040086E4,"MatchSEPlayer.inst")
 if c[0x0052]!=0x16:raise E("voice raw 0")
 tok(c,0x0053,0x6F,0x06005279,"PlayRefereeVoice")
 tok(c,0x0058,0x7E,0x04005899,"MatchUI.inst")
 if c[0x005D]!=0x17:raise E("Show_Fight raw 1")
 tok(c,0x005E,0x6F,0x060049F4,"Show_Fight")
 if c[0x0063]!=0x2A:raise E("ret")
 tok(cs["Scheduler"],0x002D,0x28,0x06005080,"FACT-0074 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"raw_state":19,"fact_0074_call":"0x002D"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_CALL_FIGHT: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_CALL_FIGHT: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
