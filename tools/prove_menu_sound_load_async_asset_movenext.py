#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00323A60
SHA="a4d0aab998a3a51651ad2a7266627226a911274f84e12043ba419b6a5325cff7"
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
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 c=body(pe,sections(pe),RVA)
 if len(c)!=147 or hashlib.sha256(c).hexdigest()!=SHA:raise E("body")
 tok(c,0x0001,0x7B,0x0400C1FB,"PC load")
 tok(c,0x0009,0x7D,0x0400C1FB,"PC -1")
 tok(c,0x0023,0x7B,0x0400C1F6,"path")
 tok(c,0x0028,0x28,0x0A000675,"Resources.LoadAsync")
 tok(c,0x002D,0x7D,0x0400C1F7,"request store")
 if c[0x0038:0x003A]!=bytes([0x16,0x8C]) or struct.unpack_from("<I",c,0x003A)[0]!=0x010000D7:raise E("boxed raw0")
 tok(c,0x003E,0x7D,0x0400C1F9,"current")
 tok(c,0x004D,0x7D,0x0400C1FB,"PC1")
 tok(c,0x0058,0x7B,0x0400C1F7,"request poll")
 tok(c,0x005D,0x6F,0x0A000676,"isDone")
 tok(c,0x0068,0x7B,0x0400C1F8,"callback gate")
 tok(c,0x0073,0x7B,0x0400C1F8,"callback load")
 tok(c,0x0079,0x7B,0x0400C1F7,"request asset")
 tok(c,0x007E,0x6F,0x0A000677,"get_asset")
 tok(c,0x0083,0x6F,0x0A000678,"callback invoke")
 tok(c,0x008A,0x7D,0x0400C1FB,"PC final")
 if c[0x008F:0x0093]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("returns")
 print("PROVE_MENU_SOUND_LOAD_ASYNC_ASSET_MOVENEXT: PASS")
if __name__=="__main__":main()
