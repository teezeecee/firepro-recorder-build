#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325D5C
SIZE=134
CODE_SHA="ea2a9629b5485ae8d47eb7166281fc0aefd20bdc8afde51a4830684d7b2406b2"
EH_HEX="011c000000001e001c3a0006c2000001000063001c7f0006c2000001"
EH_SHA="0182f6491b3e983aabf2cb42bc944c69f2225479a4b5464015a352ed7a895218"
CALLER_RVA=0x00325A80
CALLER_SHA="25cfa99ab6e97f650b4e517fa419b12acb018df2aab2933a87b40953a7084a26"
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
 if b&3==2:return {"offset":o,"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"offset":o,"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];parent=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0:raise E("header")
 if hashlib.sha256(parent).hexdigest()!=CALLER_SHA:raise E("caller")
 tok(c,0x0001,0x7B,0x040087E9,"State #1")
 if c[0x0006]!=0x17:raise E("raw1 #1")
 br(c,0x0007,0x40,0x0045,"State != raw1")
 tok(c,0x000D,0x7B,0x040087E4,"myAudioSource #1")
 tok(c,0x0012,0x6F,0x0A000CE6,"AudioSource.Pause")
 if c[0x0017:0x0019]!=bytes([0x02,0x18]):raise E("State=2 args")
 tok(c,0x0019,0x7D,0x040087E9,"State=2")
 tok(c,0x001F,0x28,0x060052CB,"FACT-0127 getter #1")
 br(c,0x0024,0x39,0x0035,"notify2 null")
 tok(c,0x002A,0x28,0x060052CB,"FACT-0127 getter #2")
 if c[0x002F]!=0x18:raise E("notify raw2")
 tok(c,0x0030,0x6F,0x0A000FC4,"Invoke raw2")
 br(c,0x0035,0xDD,0x0040,"notify2 leave")
 if c[0x003A]!=0x26:raise E("catch1 pop")
 br(c,0x003B,0xDD,0x0040,"catch1 leave")
 br(c,0x0040,0x38,0x0085,"skip second branch")
 tok(c,0x0046,0x7B,0x040087E9,"State #2")
 if c[0x004B]!=0x18:raise E("raw2 test")
 br(c,0x004C,0x40,0x0085,"State != raw2")
 tok(c,0x0052,0x7B,0x040087E4,"myAudioSource #2")
 tok(c,0x0057,0x6F,0x0A000CE8,"AudioSource.UnPause")
 if c[0x005C:0x005E]!=bytes([0x02,0x17]):raise E("State=1 args")
 tok(c,0x005E,0x7D,0x040087E9,"State=1")
 tok(c,0x0064,0x28,0x060052CB,"FACT-0127 getter #3")
 br(c,0x0069,0x39,0x007A,"notify1 null")
 tok(c,0x006F,0x28,0x060052CB,"FACT-0127 getter #4")
 if c[0x0074]!=0x17:raise E("notify raw1")
 tok(c,0x0075,0x6F,0x0A000FC4,"Invoke raw1")
 br(c,0x007A,0xDD,0x0085,"notify1 leave")
 if c[0x007F]!=0x26:raise E("catch2 pop")
 br(c,0x0080,0xDD,0x0085,"catch2 leave")
 if c[0x0085]!=0x2A:raise E("ret")
 sec=(m["offset"]+m["header"]+len(c)+3)&~3
 eh=pe[sec:sec+28]
 if eh.hex()!=EH_HEX or hashlib.sha256(eh).hexdigest()!=EH_SHA:raise E("EH")
 tok(parent,0x0019,0x28,0x060052E9,"FACT-0140 caller")
 print("PROVE_U_AUDIO_PAUSE: PASS")
if __name__=="__main__":main()
