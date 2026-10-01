#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "PlayMatchSE":(0x002B0AE4,95,"20b2b0b4629e94a1522ac997f16d94062fd0e3ad779184615939a1ee3a794aae"),
 "PlayAnimationSE":(0x002DB718,364,"ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085"),
 "ProcessCritical":(0x002E11B0,277,"95fcc98f9fe079ae95ecf2d72104145a28273b1030b2fc9db039abcfb330fd30"),
 "TransitDown":(0x002E0584,807,"279517cb863c131495de999594e2eecb0ec3cfaada975d4215ee0efd7fb2b6f6")}
class E(RuntimeError): pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def sections(pe):
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
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["PlayMatchSE"]
 tok(c,0x0000,0x7E,0x0400576C,"MatchMain.inst #1");tok(c,0x0006,0x28,0x0A00000F,"Object.op_Inequality #1")
 br(c,0x000B,0x39,0x0041,"match-null dispatch")
 tok(c,0x0010,0x7E,0x0400576C,"MatchMain.inst #2");tok(c,0x0015,0x7B,0x04005752,"isFastForwardMatch")
 br(c,0x001A,0x39,0x0041,"fast-forward false dispatch")
 tok(c,0x001F,0x7E,0x0400591E,"Fade.inst");tok(c,0x0024,0x6F,0x06004A7D,"Fade.IsFadeFinish")
 br(c,0x0029,0x39,0x0041,"fade false dispatch")
 tok(c,0x002E,0x7E,0x0400576C,"MatchMain.inst #3");tok(c,0x0033,0x7B,0x04005738,"MchFrameCnt")
 if c[0x0038:0x003B]!=bytes([0x1F,0x14,0x5E]):raise E("unsigned modulo 20")
 br(c,0x003B,0x39,0x0041,"remainder-zero dispatch")
 if c[0x0040]!=0x2A:raise E("suppressed return")
 tok(c,0x0041,0x7E,0x040086E4,"MatchSEPlayer.inst #1");tok(c,0x0047,0x28,0x0A00000F,"Object.op_Inequality #2")
 br(c,0x004C,0x39,0x005E,"player absent return")
 tok(c,0x0051,0x7E,0x040086E4,"MatchSEPlayer.inst #2")
 if c[0x0056:0x0059]!=bytes([0x02,0x03,0x04]):raise E("argument forwarding")
 tok(c,0x0059,0x6F,0x06005277,"MatchSEPlayer.PlayMatchSE")
 if c[0x005E]!=0x2A:raise E("final return")
 tok(cs["PlayAnimationSE"],0x0161,0x28,0x06004970,"FACT-0015 caller")
 tok(cs["ProcessCritical"],0x00FF,0x28,0x06004970,"FACT-0026 caller")
 tok(cs["TransitDown"],0x0321,0x28,0x06004970,"FACT-0049 caller")
 pc=cs["ProcessCritical"]
 if pc[0x00F2:0x00F4]!=bytes([0x1F,0x1E]):raise E("critical seid 30")
 f32(pc,0x00F4,1.0,"critical vol")
 td=cs["TransitDown"]
 if td[0x0314:0x0316]!=bytes([0x1F,0x43]):raise E("down seid 67")
 f32(td,0x0316,1.0,"down vol")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["PlayMatchSE"][2]},"canonical_callers":["FACT-0015","FACT-0026","FACT-0049"]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_PLAY_MATCH_SE: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_PLAY_MATCH_SE: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
