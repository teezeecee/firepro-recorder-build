#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
CTOR_RVA=0x00325627; CTOR_SHA="b3886117f8449c5a0bb1c948786b6cf3ecbfd14d7caee2594f9fb9cdcdc30b5e"
AWAKE_RVA=0x00325648; AWAKE_SHA="ff82e2f96702dc7b19840d6fe9cfa849d45c0fd7a749b317b93de5377869aa7e"
CTOR=bytes.fromhex("02220000803f7df0870004027ebd0f000a7df287000402280e00000a2a")
AWAKE=bytes.fromhex("027be487000414280600000a39170000007286ea0870286206000a0a02066f4c00002b7de48700042a")
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]; n=struct.unpack_from("<H",pe,q+6)[0]; opt=struct.unpack_from("<H",pe,q+20)[0]; so=q+24+opt; out=[]
 for i in range(n):
  o=so+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def locate(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise E("rva")
def body(pe,ss,rva):
 o=locate(ss,rva); b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)],("tiny",8,0)
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n],("fat",struct.unpack_from("<H",pe,o+2)[0],struct.unpack_from("<I",pe,o+8)[0])
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 c,ch=body(pe,ss,CTOR_RVA); w,wh=body(pe,ss,AWAKE_RVA)
 if c!=CTOR or hashlib.sha256(c).hexdigest()!=CTOR_SHA:raise E("ctor")
 if w!=AWAKE or hashlib.sha256(w).hexdigest()!=AWAKE_SHA:raise E("awake")
 if ch!=("tiny",8,0):raise E("ctor header")
 if wh!=("fat",2,0x1100000A):raise E("awake header")
 if c[1:6]!=bytes.fromhex("220000803f"):raise E("ctor float 1")
 if c[6]!=0x7D or struct.unpack_from("<I",c,7)[0]!=0x040087F0:raise E("volume offset")
 if c[12]!=0x7E or struct.unpack_from("<I",c,13)[0]!=0x0A000FBD:raise E("TimeSpan.Zero")
 if c[17]!=0x7D or struct.unpack_from("<I",c,18)[0]!=0x040087F2:raise E("endSongTime")
 if c[23]!=0x28 or struct.unpack_from("<I",c,24)[0]!=0x0A00000E:raise E("base ctor")
 if w[1]!=0x7B or struct.unpack_from("<I",w,2)[0]!=0x040087E4:raise E("awake field gate")
 if w[7]!=0x28 or struct.unpack_from("<I",w,8)[0]!=0x0A000006:raise E("Object equality")
 if w[17]!=0x72 or struct.unpack_from("<I",w,18)[0]!=0x7008EA86:raise E("Sound_Manager")
 if w[22]!=0x28 or struct.unpack_from("<I",w,23)[0]!=0x0A000662:raise E("GameObject.Find")
 if w[30]!=0x6F or struct.unpack_from("<I",w,31)[0]!=0x2B00004C:raise E("AddComponent AudioSource MethodSpec")
 if w[35]!=0x7D or struct.unpack_from("<I",w,36)[0]!=0x040087E4:raise E("audio source store")
 for tok in (0x060052C8,0x060052C9):
  t=struct.pack("<I",tok)
  for pre in (b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"):
   if pe.find(pre+t)>=0:raise E("direct inbound reference "+hex(tok))
 print("PROVE_U_AUDIO_INIT_LIFECYCLE: PASS")
if __name__=="__main__":main()
