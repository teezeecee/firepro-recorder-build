#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS={
0x00321A30:(15,"65d2fa09b6d7e4734ea6ced8c7df63053cd00416b490ac5bbbebc2900df6eca3","73b97400060a06027df1c10004062a"),
0x00323898:(7,"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9","0228ef00000a2a"),
0x00323A15:(7,"2a8bce63c14acba20ed3137df6f67799c50ca87fe09910f877deff0c540107c9","027bf2c100042a"),
0x00323A1D:(7,"2a8bce63c14acba20ed3137df6f67799c50ca87fe09910f877deff0c540107c9","027bf2c100042a"),
0x00323A25:(15,"844c294556c005d033b9b34558cf81e6ab28fcad3a83d72f006f969706a2b0ff","02177df3c1000402157df4c100042a"),
0x00323A35:(6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49","73ee00000a7a")
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
 ss=sections(pe)
 got={}
 for rva,(size,sha,hx) in METHODS.items():
  c=body(pe,ss,rva);got[rva]=c
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha or c.hex()!=hx:raise E(hex(rva))
 f=got[0x00321A30]
 if f[0]!=0x73 or struct.unpack_from("<I",f,1)[0]!=0x060074B9:raise E("factory ctor")
 if f[7]!=0x02 or f[8]!=0x7D or struct.unpack_from("<I",f,9)[0]!=0x0400C1F1:raise E("factory captured this")
 print("PROVE_MENU_SOUND_LOAD_MATCH_SE_FACTORY_SUPPORT: PASS")
if __name__=="__main__":main()
