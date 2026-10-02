#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006F1C8
SIZE=58
CODE_SHA="3e6d24308c5d970566cd1d5d912792e1ff4ba9bbc71aad81a62da600b2b772c4"
CALLER_RVA=0x002DE53C
CALLER_SIZE=272
CALLER_SHA="827f27896099f2fabf61cc8659bb91cfd1ef7c2cccee142cd3e754ba3e577d8d"
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
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];p=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0x1100034D:raise E("header")
 if len(p)!=CALLER_SIZE or hashlib.sha256(p).hexdigest()!=CALLER_SHA:raise E("caller body")
 if c[0:2]!=bytes([0x02,0x03]):raise E("this/type args")
 tok(c,0x0002,0x28,0x060011E7,"FACT-0181 GetWrestlerVoiceInfo")
 if c[0x0007:0x0009]!=bytes([0x0A,0x06]):raise E("local info")
 br(c,0x0009,0x3A,0x0015,"info non-null")
 if c[0x000E]!=0x02:raise E("fallback this #1")
 tok(c,0x000F,0x7B,0x040011E8,"fallback #1")
 if c[0x0014]!=0x2A:raise E("fallback ret #1")
 if c[0x0015:0x0017]!=bytes([0x04,0x06]):raise E("idx/info")
 tok(c,0x0017,0x7B,0x040011E3,"attr for count")
 tok(c,0x001C,0x6F,0x0A00078A,"get_Count")
 br(c,0x0021,0x3F,0x002D,"signed idx < Count")
 if c[0x0026]!=0x02:raise E("fallback this #2")
 tok(c,0x0027,0x7B,0x040011E8,"fallback #2")
 if c[0x002C]!=0x2A:raise E("fallback ret #2")
 if c[0x002D]!=0x06:raise E("info item")
 tok(c,0x002E,0x7B,0x040011E3,"attr for item")
 if c[0x0033]!=0x04:raise E("idx item")
 tok(c,0x0034,0x6F,0x0A00078B,"get_Item")
 if c[0x0039]!=0x2A:raise E("item ret")
 tok(p,0x00EC,0x6F,0x060011E8,"Player.PlayWrestlerVoice direct caller")
 print("PROVE_WRESTLER_VOICE_INFO_MANAGER_GET_ATTR: PASS")
if __name__=="__main__":main()
