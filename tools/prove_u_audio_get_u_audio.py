#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325714
SIZE=86
CODE_SHA="5524703abb8912537cca2bf60cf25fdcde63df8bcc2ea51a0db76d5dc8e858c4"
CALLER_RVA=0x00325A30
CALLER_SHA="b5b74da6ab2322d1895635e2add04dd52f9ee9ca4a3846825a9b6fe4631e3ef4"
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
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=3 or m["local_sig"]!=0:raise E("header")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0]!=0x02:raise E("backend receiver")
 tok(c,0x0001,0x7B,0x040087E3,"_uAudio gate")
 br(c,0x0006,0x3A,0x004F,"backend exists")
 if c[0x000B]!=0x02:raise E("ctor store receiver")
 tok(c,0x000C,0x73,0x0A000FB1,"backend ctor")
 tok(c,0x0011,0x7D,0x040087E3,"_uAudio store")
 if c[0x0016]!=0x02:raise E("SetAudioFile owner")
 tok(c,0x0017,0x7B,0x040087E3,"_uAudio #1")
 if c[0x001C]!=0x02:raise E("target owner")
 tok(c,0x001D,0x7B,0x040087E6,"targetFile")
 tok(c,0x0022,0x6F,0x0A000FB2,"SetAudioFile")
 if c[0x0027]!=0x02:raise E("volume owner")
 tok(c,0x0028,0x7B,0x040087E3,"_uAudio #2")
 if c[0x002D]!=0x02:raise E("offset owner")
 tok(c,0x002E,0x7B,0x040087F0,"start_volume_Offset")
 tok(c,0x0033,0x6F,0x0A000FB0,"set_Volume")
 if c[0x0038]!=0x02:raise E("callback owner")
 tok(c,0x0039,0x7B,0x040087E3,"_uAudio #3")
 if c[0x003E]!=0x02 or c[0x003F:0x0041]!=bytes([0xFE,0x06]):raise E("delegate target/ldftn")
 if struct.unpack_from("<I",c,0x0041)[0]!=0x060052EE:raise E("callback method")
 tok(c,0x0045,0x73,0x0A000FB3,"Action<PlayBackState> ctor")
 tok(c,0x004A,0x6F,0x0A000FB4,"set_sendPlaybackState")
 if c[0x004F]!=0x02:raise E("return owner")
 tok(c,0x0050,0x7B,0x040087E3,"_uAudio return")
 if c[0x0055]!=0x2A:raise E("ret")
 for off in (0x0013,0x0035):tok(cc,off,0x28,0x060052D0,"FACT-0137 caller")
 print("PROVE_U_AUDIO_GET_U_AUDIO: PASS")
if __name__=="__main__":main()
