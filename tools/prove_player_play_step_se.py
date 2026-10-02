#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002DE658;SIZE=171;CODE_SHA="efbedac2c1bed8042849458be9e4aab0aff8bbe2e7f42d4ca0a31ce98fd698dc"
FACT0015_RVA=0x002DB718;FACT0015_SHA="ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085"
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
 return {"offset":o,"header":h,"flags":fs&0xFFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];p=method(pe,ss,FACT0015_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=3 or m["local_sig"]!=0x11001064:raise E("header")
 if hashlib.sha256(p).hexdigest()!=FACT0015_SHA:raise E("FACT0015")
 if c[0:6]!=bytes.fromhex("220000803f0a"):raise E("volume init")
 tok(c,0x0006,0x7E,0x0400607A,"on_mat_tbl")
 if c[0x000B]!=0x0B:raise E("stloc1")
 tok(c,0x000C,0x7E,0x04002AD1,"GlobalWork.inst")
 tok(c,0x0011,0x7B,0x04002AD2,"MatchSetting")
 if c[0x0016]!=0x0C:raise E("stloc2")
 for off,val,target in [(0x0017,9,0x0049),(0x0024,10,0x0049)]:
  if c[off]!=0x02:raise E("zone this")
  tok(c,off+1,0x7B,0x04005FEE,"Zone")
  if c[off+6:off+8]!=bytes([0x1F,val]):raise E("zone raw")
  br(c,off+8,0x3B,target,"zone eq")
 if c[0x0031]!=0x02:raise E("zone3 this")
 tok(c,0x0032,0x7B,0x04005FEE,"Zone3")
 if c[0x0037]!=0x19:raise E("zone3 raw")
 br(c,0x0038,0x3B,0x0049,"zone3 eq")
 if c[0x003D]!=0x02:raise E("zone8 this")
 tok(c,0x003E,0x7B,0x04005FEE,"Zone8")
 if c[0x0043]!=0x1E:raise E("zone8 raw")
 br(c,0x0044,0x40,0x0054,"zone8 bne")
 tok(c,0x0049,0x7E,0x0400607B,"on_stage_tbl")
 if c[0x004E]!=0x0B:raise E("stage stloc")
 br(c,0x004F,0x38,0x0095,"stage join")
 if c[0x0054]!=0x02:raise E("FormRen this")
 tok(c,0x0055,0x7B,0x04005FA7,"FormRen")
 tok(c,0x005A,0x7B,0x04002744,"pos_OutOfRing")
 br(c,0x005F,0x39,0x0095,"not out-of-ring join")
 if c[0x0064]!=0x08:raise E("arena9 local2")
 tok(c,0x0065,0x7B,0x040057D4,"arena9")
 if c[0x006A:0x006C]!=bytes([0x1F,0x09]):raise E("arena9 raw")
 br(c,0x006C,0x3B,0x007E,"arena9 eq")
 if c[0x0071]!=0x08:raise E("arena10 local2")
 tok(c,0x0072,0x7B,0x040057D4,"arena10")
 if c[0x0077:0x0079]!=bytes([0x1F,0x0A]):raise E("arena10 raw")
 br(c,0x0079,0x40,0x0089,"arena10 bne")
 tok(c,0x007E,0x7E,0x0400607D,"on_birbed_wire")
 if c[0x0083]!=0x0B:raise E("barbed stloc")
 br(c,0x0084,0x38,0x0095,"barbed join")
 tok(c,0x0089,0x7E,0x0400607C,"out_of_ring_tbl")
 if c[0x008E]!=0x0B:raise E("out stloc")
 if c[0x008F:0x0095]!=bytes.fromhex("229a99193f0a"):raise E("raw 0.6 volume")
 if c[0x0095:0x0098]!=bytes([0x07,0x16,0x19]):raise E("table/range args")
 tok(c,0x0098,0x28,0x0600497B,"FACT0032 Range")
 if c[0x009D]!=0x94:raise E("ldelem.i4")
 if c[0x009E:0x00A0]!=bytes([0x06,0x02]):raise E("volume/this")
 tok(c,0x00A0,0x7B,0x04005FA6,"PlIdx")
 tok(c,0x00A5,0x28,0x06004970,"FACT0058 PlayMatchSE")
 if c[0x00AA]!=0x2A:raise E("ret")
 tok(p,0x014A,0x6F,0x06004EB5,"FACT0015 inbound")
 print("PROVE_PLAYER_PLAY_STEP_SE: PASS")
if __name__=="__main__":main()
