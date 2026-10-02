#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
0x00322E78:(bytes.fromhex("7eeb8600041d9a0a066fc45200062a"),"bd09c857a08a9f181430706d332d7fc7b542cbc2ab2f270573532874cfc8f92c"),
0x003230A8:(bytes.fromhex("7eeb860004029a0a066fc45200062a"),"71081b697f7337a53855cbe29050aca01c20cb62f8efbd862eeb4772aa565100")
}
FACT0125_RVA=0x00323806
FACT0125_SHA="6367793f54b558ae8629023c6246cc6a97b366e8e4cf5761be3343d3cafcb76a"
class E(RuntimeError):pass
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return (pe[o+1:o+1+(b>>2)],2,8,0)
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return (pe[o+h:o+h+n],fs&0x0FFF,struct.unpack_from("<H",pe,o+2)[0],struct.unpack_from("<I",pe,o+8)[0])
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=secs(pe)
 stop125,_,_,_=method(pe,ss,FACT0125_RVA)
 if len(stop125)!=43 or hashlib.sha256(stop125).hexdigest()!=FACT0125_SHA:raise E("FACT-0125")
 for rva,(exp,sha) in M.items():
  c,flags,maxs,loc=method(pe,ss,rva)
  if c!=exp or hashlib.sha256(c).hexdigest()!=sha:raise E(hex(rva))
  if flags!=0x0013 or maxs!=2 or loc!=0x1100120B:raise E("header "+hex(rva))
  if c[0]!=0x7E or struct.unpack_from("<I",c,1)[0]!=0x040086EB:raise E("audioSrcInfo "+hex(rva))
  if c[6]!=0x9A or c[7]!=0x0A or c[8]!=0x06:raise E("selection/local "+hex(rva))
  if c[9]!=0x6F or struct.unpack_from("<I",c,10)[0]!=0x060052C4 or c[14]!=0x2A:raise E("FACT-0125 call "+hex(rva))
 if M[0x00322E78][0][5]!=0x1D:raise E("raw7")
 if M[0x003230A8][0][5]!=0x02:raise E("slot arg")
 print("PROVE_MENU_SOUND_STOP_WRAPPERS: PASS")
if __name__=="__main__":main()
