#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003259C8
SIZE=141
CODE_SHA="3ff6f18fdb7ed86c92f309f6496f6d7fc3a7cee75b55c9174345fac0efaeee4c"
CALLER_RVA=0x0032567D
CALLER_SHA="62a68c749da17a7c536b2ef155fd300637ffd8bd582da8979c28fdd87bf83d1c"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def locate(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise E("rva")
def method(pe,ss,rva):
 o=locate(ss,rva);b=pe[o]
 if b&3==2:return {"offset":o,"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"offset":o,"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];cc=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0:raise E("header")
 if c[0:2]!=bytes([0x02,0x02]):raise E("current time receiver")
 tok(c,0x0002,0x28,0x060052D6,"get_CurrentTime")
 tok(c,0x0007,0x7D,0x040087F2,"endSongTime")
 if c[0x000C]!=0x02:raise E("stream receiver")
 tok(c,0x000D,0x7B,0x040087EF,"readFullyStream #1")
 br(c,0x0012,0x39,0x0022,"stream null")
 if c[0x0017]!=0x02:raise E("stream receiver #2")
 tok(c,0x0018,0x7B,0x040087EF,"readFullyStream #2")
 tok(c,0x001D,0x6F,0x0A000154,"Stream.Close")
 if c[0x0022]!=0x02:raise E("audio source receiver")
 tok(c,0x0023,0x7B,0x040087E4,"myAudioSource stop")
 tok(c,0x0028,0x6F,0x0A00079F,"AudioSource.Stop")
 if c[0x002D]!=0x02:raise E("backend receiver")
 tok(c,0x002E,0x7B,0x040087E3,"_uAudio")
 tok(c,0x0033,0x6F,0x0A000FC3,"backend Stop")
 if c[0x0038]!=0x02:raise E("clip receiver")
 tok(c,0x0039,0x7B,0x040087E4,"myAudioSource clip")
 if c[0x003E]!=0x14:raise E("null clip")
 tok(c,0x003F,0x6F,0x0A00079B,"AudioSource.set_clip")
 if c[0x0044:0x0046]!=bytes([0x02,0x16]):raise E("updateTime zero")
 tok(c,0x0046,0x7D,0x040087EA,"updateTime")
 if c[0x004B:0x004D]!=bytes([0x02,0x16]):raise E("loadedTarget zero")
 tok(c,0x004D,0x7D,0x040087F1,"_loadedTarget")
 if c[0x0052:0x0054]!=bytes([0x02,0x16]):raise E("State zero")
 tok(c,0x0054,0x7D,0x040087E9,"State")
 if c[0x0059]!=0x02:raise E("callback receiver #1")
 tok(c,0x005A,0x28,0x060052CB,"get_sendPlaybackState #1")
 br(c,0x005F,0x39,0x0070,"callback null")
 if c[0x0064]!=0x02:raise E("callback receiver #2")
 tok(c,0x0065,0x28,0x060052CB,"get_sendPlaybackState #2")
 if c[0x006A]!=0x16:raise E("raw callback zero")
 tok(c,0x006B,0x6F,0x0A000FC4,"callback Invoke")
 br(c,0x0070,0xDD,0x007B,"inner try leave")
 if c[0x0075]!=0x26:raise E("inner catch pop")
 br(c,0x0076,0xDD,0x007B,"inner catch leave")
 br(c,0x007B,0xDD,0x008C,"outer try leave")
 if c[0x0080]!=0x26:raise E("outer catch pop")
 tok(c,0x0081,0x72,0x7008F3A4,"exception user string")
 tok(c,0x0086,0x73,0x0A000499,"Exception ctor")
 if c[0x008B:0x008D]!=bytes([0x7A,0x2A]):raise E("throw/ret")
 end=(m["offset"]+m["header"]+len(c)+3)&~3
 sec=pe[end:end+28]
 if sec[0]!=0x01 or sec[1]!=0x1C:raise E("EH header")
 clauses=[]
 for i in range(2):
  x=sec[4+i*12:4+(i+1)*12]
  clauses.append((struct.unpack_from("<H",x,0)[0],struct.unpack_from("<H",x,2)[0],x[4],struct.unpack_from("<H",x,5)[0],x[7],struct.unpack_from("<I",x,8)[0]))
 if clauses[0]!=(0,0x0059,28,0x0075,6,0x010000C2):raise E("inner EH")
 if clauses[1]!=(0,0x0000,128,0x0080,12,0x010000C2):raise E("outer EH")
 tok(cc,0x0001,0x28,0x060052E6,"FACT-0124 caller")
 print("PROVE_U_AUDIO_SONG_END: PASS")
if __name__=="__main__":main()
