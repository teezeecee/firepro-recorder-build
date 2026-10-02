#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
0x00321CE4:(15,"506732d3b9f0d6b4d7a4cf027d9a8c32bb1764f113000e24f2f72153caf4eb27"),
0x00324468:(7,"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9"),
0x003245B3:(7,"7e051e009393a0bf301de63967a42a8a685c359901912dab800489ebea628d82"),
0x003245BB:(7,"7e051e009393a0bf301de63967a42a8a685c359901912dab800489ebea628d82"),
0x003245C3:(15,"87a280b69c2e509c151ab7901bb1eb163b4b8430c9f1d19de91344c7970f9657"),
0x003245D3:(6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49"),
0x00324470:(311,"b7cd1752de05dfc07cc79a9b416fd025358fd0f6d9041e7c03f72b564c054b64")
}
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);bodies={}
 for rva,(size,sha) in M.items():
  c=body(pe,ss,rva);bodies[rva]=c
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(hex(rva))
 f=bodies[0x00321CE4]
 if f[0]!=0x73 or struct.unpack_from("<I",f,1)[0]!=0x060074D1:raise E("factory ctor")
 if f[5:8]!=bytes([0x0A,0x06,0x02]):raise E("factory local/type args")
 if f[8]!=0x7D or struct.unpack_from("<I",f,9)[0]!=0x0400C21B or f[13:15]!=bytes([0x06,0x2A]):raise E("factory type store/return")
 c=bodies[0x00324468]
 if c!=bytes.fromhex("0228ef00000a2a"):raise E("ctor")
 for rva in (0x003245B3,0x003245BB):
  if bodies[rva]!=bytes.fromhex("027b1ec200042a"):raise E("Current")
 if bodies[0x003245C3]!=bytes.fromhex("02177d1fc2000402157d20c200042a"):raise E("Dispose")
 if bodies[0x003245D3]!=bytes.fromhex("73ee00000a7a"):raise E("Reset")
 print("PROVE_MENU_SOUND_LOAD_ASYNC_REFEREE_VOICE_FACTORY_SUPPORT: PASS")
if __name__=="__main__":main()
