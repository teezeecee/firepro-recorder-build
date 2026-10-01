#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325A30
SIZE=65
CODE_SHA="b5b74da6ab2322d1895635e2add04dd52f9ee9ca4a3846825a9b6fe4631e3ef4"
CALLER_RVA=0x00323130
CALLER_SHA="e84b8a91478acffadf8ee5f39f17855e421d0cf1b4d482f97dfbb53700440a5a"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];cc=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0:raise E("header")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0:2]!=bytes([0x02,0x03]):raise E("target store args")
 tok(c,0x0002,0x7D,0x040087E6,"targetFile store")
 if c[0x0007]!=0x02:raise E("loaded receiver")
 tok(c,0x0008,0x7B,0x040087F1,"_loadedTarget")
 br(c,0x000D,0x39,0x002D,"loaded false")
 if c[0x0012]!=0x02:raise E("get_UAudio receiver #1")
 tok(c,0x0013,0x28,0x060052D0,"get_UAudio #1")
 tok(c,0x0018,0x7B,0x0A000FC1,"backend targetFile")
 if c[0x001D]!=0x02:raise E("target receiver #2")
 tok(c,0x001E,0x7B,0x040087E6,"targetFile load")
 tok(c,0x0023,0x28,0x0A000030,"String.op_Inequality")
 br(c,0x0028,0x39,0x0040,"same target return")
 if c[0x002D:0x002F]!=bytes([0x02,0x17]):raise E("loaded true args")
 tok(c,0x002F,0x7D,0x040087F1,"_loadedTarget true")
 if c[0x0034]!=0x02:raise E("get_UAudio receiver #2")
 tok(c,0x0035,0x28,0x060052D0,"get_UAudio #2")
 if c[0x003A]!=0x03:raise E("targetFileIN forward")
 tok(c,0x003B,0x6F,0x0A000FC2,"backend LoadFile")
 if c[0x0040]!=0x2A:raise E("ret")
 for off in (0x00E3,0x019A):tok(cc,off,0x6F,0x060052E4,"FACT-0133 caller")
 print("PROVE_U_AUDIO_LOAD_FILE: PASS")
if __name__=="__main__":main()
