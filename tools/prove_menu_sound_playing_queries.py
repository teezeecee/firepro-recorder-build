#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
Q=[
 (0x00322908,bytes.fromhex("7eeb860004169a0a067b4c8700046fae0c000a2a"),"f443c2451dd1f05f72b0fdf52010f2bdf11af076ba3d8cd82f5d819114b82b62",0),
 (0x00322CA0,bytes.fromhex("7eeb8600041a9a0a067b4c8700046fae0c000a2a"),"73b973ba207b6764e96da5c8b6513177be2d821c9f0bbbdf234ebd4d13290b2c",4)]
CALLERS=[
 (0x00305E08,"9b1289adbe32d2145b2ff9a35d89323d7fc3fbb26ec0d59c49af3f85b115bffe",0x041F,0x060052A0),
 (0x00153F90,"f4f823f813f84b79c2e1c95458a3aad3e06901cf453e88f6b8e6d3d295af4d67",0x007D,0x060052AA)]
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"code":pe[o+1:o+1+(b>>2)],"flags":2,"max_stack":8,"local_sig":0}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"code":pe[o+h:o+h+n],"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 for rva,exp,sha,idx in Q:
  m=method(pe,ss,rva);c=m["code"]
  if c!=exp or len(c)!=20 or hashlib.sha256(c).hexdigest()!=sha:raise E("query body "+hex(rva))
  if m["flags"]!=0x0013 or m["max_stack"]!=2 or m["local_sig"]!=0x1100120B:raise E("query header")
  if c[0]!=0x7E or struct.unpack_from("<I",c,1)[0]!=0x040086EB:raise E("audioSrcInfo")
  expected_idx={0:0x16,4:0x1A}[idx]
  if c[5]!=expected_idx or c[6]!=0x9A or c[7]!=0x0A or c[8]!=0x06:raise E("fixed index/local")
  if c[9]!=0x7B or struct.unpack_from("<I",c,10)[0]!=0x0400874C:raise E("sRefAudio")
  if c[14]!=0x6F or struct.unpack_from("<I",c,15)[0]!=0x0A000CAE or c[19]!=0x2A:raise E("get_isPlaying/ret")
 for rva,sha,off,target in CALLERS:
  c=method(pe,ss,rva)["code"]
  if hashlib.sha256(c).hexdigest()!=sha:raise E("caller hash")
  if c[off]!=0x28 or struct.unpack_from("<I",c,off+1)[0]!=target:raise E("caller direct ref")
 print("PROVE_MENU_SOUND_PLAYING_QUERIES: PASS")
if __name__=="__main__":main()
