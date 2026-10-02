#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0032344C
SHA="3e652f9ec0ddcdd64c52c9cba261a1f70bba3ffa41ff4296d6eba45e6514b378"
CALLER_RVA=0x00197B38
CALLER_SHA="14129c14ca6039a686af85c9de4920278e34dfb0910593b988ad62fa16417195"
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
 ss=sections(pe)
 c=body(pe,ss,RVA)
 if c!=bytes.fromhex("172a") or hashlib.sha256(c).hexdigest()!=SHA:raise E("IsWaitBGM_MP3 body")
 caller=body(pe,ss,CALLER_RVA)
 if len(caller)!=1048 or hashlib.sha256(caller).hexdigest()!=CALLER_SHA:raise E("Dialog_Skill.Update body")
 if caller[0x0267:0x026C]!=bytes.fromhex("28bd520006"):raise E("caller site")
 target=struct.pack("<I",0x060052BD)
 count=0
 for pre in (b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"):
  start=0
  while True:
   i=pe.find(pre+target,start)
   if i<0:break
   count+=1;start=i+1
 if count!=1:raise E("direct reference count")
 print("PROVE_MENU_SOUND_IS_WAIT_BGM_MP3: PASS")
if __name__=="__main__":main()
