#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00322F34;SIZE=125
CODE_SHA="89b773f755d9066b9ae0731733012e2c12839acab2548a261e022dbf7b158c12"
FACT0187_RVA=0x002DE53C
FACT0187_SHA="827f27896099f2fabf61cc8659bb91cfd1ef7c2cccee142cd3e754ba3e577d8d"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"offset":o,"header":1,"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"offset":o,"header":h,"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];p=method(pe,ss,FACT0187_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=3 or m["local_sig"]!=0x1100120F:raise E("header")
 if hashlib.sha256(p).hexdigest()!=FACT0187_SHA:raise E("FACT-0187 body")
 tok(c,0x0000,0x7E,0x040086FD,"Sound_ClipWrestlerVoice_List")
 br(c,0x0005,0x3A,0x000B,"clip table non-null")
 if c[0x000A]!=0x2A:raise E("clip table null return")
 if c[0x000B:0x000D]!=bytes([0x02,0x16]):raise E("pl_idx lower setup")
 br(c,0x000D,0x3F,0x0019,"pl_idx lower gate")
 if c[0x0012:0x0014]!=bytes([0x02,0x1E]):raise E("pl_idx upper setup")
 br(c,0x0014,0x3F,0x001A,"pl_idx upper gate")
 if c[0x0019]!=0x2A:raise E("pl_idx range return")
 tok(c,0x001A,0x7E,0x040086FD,"clip table load")
 if c[0x001F:0x0021]!=bytes([0x02,0x03]):raise E("clip Get args")
 tok(c,0x0021,0x28,0x0A000FA4,"AudioClip[,] Get")
 if c[0x0026]!=0x0A:raise E("stloc0")
 if c[0x0027:0x0029]!=bytes([0x06,0x14]):raise E("clip null setup")
 tok(c,0x0029,0x28,0x0A000006,"Object equality")
 br(c,0x002E,0x39,0x0034,"clip non-null")
 if c[0x0033]!=0x2A:raise E("clip null return")
 tok(c,0x0034,0x7E,0x040086EF,"Volume_Voice")
 if c[0x0039:0x003C]!=bytes([0x04,0x5A,0x0B]):raise E("volume multiply/store")
 if c[0x003C]!=0x07 or c[0x003D:0x0042]!=bytes.fromhex("2200000000"):raise E("volume lower setup")
 br(c,0x0042,0x41,0x0048,"volume bge.un zero")
 if c[0x0047]!=0x2A:raise E("ordered negative return")
 if c[0x0048]!=0x07 or c[0x0049:0x004E]!=bytes.fromhex("220000803f"):raise E("volume upper setup")
 br(c,0x004E,0x43,0x0059,"volume ble.un one")
 if c[0x0053:0x0059]!=bytes.fromhex("220000803f0b"):raise E("volume upper clamp")
 tok(c,0x0059,0x7E,0x040086EB,"audioSrcInfo")
 tok(c,0x005E,0x7E,0x040086F5,"audio_source_index")
 if c[0x0063:0x0067]!=bytes([0x19,0x58,0x9A,0x0C]):raise E("audioSrcInfo[index+3]")
 if c[0x0067]!=0x08:raise E("local2")
 tok(c,0x0068,0x7B,0x0400874C,"sRefAudio")
 if c[0x006D:0x006F]!=bytes([0x0D,0x09]):raise E("local3")
 if c[0x006F]!=0x07:raise E("volume local")
 tok(c,0x0070,0x6F,0x0A0002A2,"AudioSource.set_volume")
 if c[0x0075:0x0077]!=bytes([0x09,0x06]):raise E("PlayOneShot args")
 tok(c,0x0077,0x6F,0x0A000FA6,"AudioSource.PlayOneShot")
 if c[0x007C]!=0x2A:raise E("ret")
 tok(p,0x00B8,0x28,0x060052B1,"FACT-0187 inbound caller")
 print("PROVE_MENU_SOUND_PLAY_WRESTLER_VOICE: PASS")
if __name__=="__main__":main()
