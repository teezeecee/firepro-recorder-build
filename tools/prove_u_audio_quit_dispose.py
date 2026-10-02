#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
Q_RVA=0x00325E1F; Q_SHA="7a7dcc5d4b3ee0bb1933833a4e1db71ee2f4720b7d7084aea7ccca1bee9c4ee4"
D_RVA=0x00325E27; D_SHA="e67d4211a0c7ec2b2eb5a67f694a81c4e43c78972d036dd2e856f8573244884c"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]; n=struct.unpack_from("<H",pe,q+6)[0]; z=struct.unpack_from("<H",pe,q+20)[0]; s=q+24+z; out=[]
 for i in range(n):
  o=s+i*40; vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);q=body(pe,ss,Q_RVA);d=body(pe,ss,D_RVA)
 if len(q)!=7 or hashlib.sha256(q).hexdigest()!=Q_SHA:raise E("quit")
 if q[0]!=0x02:raise E("quit this")
 tok(q,1,0x28,0x060052EC,"quit Dispose")
 if q[6]!=0x2A:raise E("quit ret")
 if len(d)!=59 or hashlib.sha256(d).hexdigest()!=D_SHA:raise E("dispose")
 if d[0]!=0x02:raise E("read stream this")
 tok(d,1,0x7B,0x040087EF,"readFullyStream gate")
 br(d,6,0x39,0x16,"stream null")
 if d[0x0B]!=0x02:raise E("stream this")
 tok(d,0x0C,0x7B,0x040087EF,"readFullyStream close")
 tok(d,0x11,0x6F,0x0A000154,"Stream.Close")
 if d[0x16]!=0x02:raise E("backend this")
 tok(d,0x17,0x7B,0x040087E3,"backend gate")
 br(d,0x1C,0x39,0x33,"backend null")
 if d[0x21]!=0x02:raise E("backend this #2")
 tok(d,0x22,0x7B,0x040087E3,"backend load")
 tok(d,0x27,0x6F,0x0A000FD5,"backend Dispose")
 if d[0x2C:0x2E]!=bytes([0x02,0x14]):raise E("backend null args")
 tok(d,0x2E,0x7D,0x040087E3,"backend null store")
 if d[0x33:0x35]!=bytes([0x02,0x16]):raise E("loaded false args")
 tok(d,0x35,0x7D,0x040087F1,"loadedTarget false")
 if d[0x3A]!=0x2A:raise E("dispose ret")
 print("PROVE_U_AUDIO_QUIT_DISPOSE: PASS")
if __name__=="__main__":main()
