#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325CF4
SIZE=73
CODE_SHA="2834d930fa5659f589d893b94877b0b1b3462054322124cc7e1124abb3e8ae39"
EH_HEX="011000000000000042420006d2000001"
EH_SHA="6a80fae31f6fc3bf241bdd460e4208a9fd322a555b82a612da16d0b82c9adab2"
PARENT_RVA=0x00325A80
PARENT_SHA="25cfa99ab6e97f650b4e517fa419b12acb018df2aab2933a87b40953a7084a26"
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
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];p=method(pe,ss,PARENT_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=4 or m["local_sig"]!=0x11001221:raise E("header")
 if hashlib.sha256(p).hexdigest()!=PARENT_SHA:raise E("parent")
 if c[0]!=0x02:raise E("this SongDone")
 tok(c,0x0001,0x7B,0x040087EB,"SongDone")
 br(c,0x0006,0x3A,0x0036,"SongDone true")
 if c[0x000B]!=0x02:raise E("this playbackDevice")
 tok(c,0x000C,0x7B,0x040087EE,"playbackDevice")
 if c[0x0011:0x0014]!=bytes([0x03,0x16,0x03]):raise E("Read args")
 if c[0x0014:0x0016]!=bytes([0x8E,0x69]):raise E("data.Length conv")
 tok(c,0x0016,0x6F,0x0A000FD4,"MpegFile.Read")
 if c[0x001B]!=0x0A or c[0x001C:0x001E]!=bytes([0x06,0x16]):raise E("count local")
 br(c,0x001E,0x3D,0x002A,"count > 0")
 if c[0x0023:0x0025]!=bytes([0x02,0x17]):raise E("SongDone=true args")
 tok(c,0x0025,0x7D,0x040087EB,"SongDone=true")
 if c[0x002A:0x002C]!=bytes([0x02,0x16]):raise E("destroy=false args")
 tok(c,0x002C,0x7D,0x040087E8,"flg_source_destroy=false")
 br(c,0x0031,0x38,0x003D,"normal join")
 if c[0x0036:0x0038]!=bytes([0x02,0x17]):raise E("destroy=true args")
 tok(c,0x0038,0x7D,0x040087E8,"flg_source_destroy=true")
 br(c,0x003D,0xDD,0x0048,"normal leave")
 if c[0x0042]!=0x0B:raise E("exception local1")
 br(c,0x0043,0xDD,0x0048,"catch leave")
 if c[0x0048]!=0x2A:raise E("ret")
 sec=(m["offset"]+m["header"]+len(c)+3)&~3
 eh=pe[sec:sec+16]
 if eh.hex()!=EH_HEX or hashlib.sha256(eh).hexdigest()!=EH_SHA:raise E("EH")
 if p[0x0070:0x0072]!=bytes([0xFE,0x06]) or struct.unpack_from("<I",p,0x0072)[0]!=0x060052E8:raise E("FACT-0140 ldftn")
 print("PROVE_U_AUDIO_SONG_STREAM_LOOP: PASS")
if __name__=="__main__":main()
