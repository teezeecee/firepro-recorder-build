#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS={
0x00321C54:(22,"0b3dccaf04ab02d9fd75b42e066f836adf54e8527cbcd19cdf6f30b73fcaddf7","73cb7400060a06027d07c2000406037d11c20004062a"),
0x00321D6C:(22,"0413ed4cc600423712fb04ffb304151d30a4e14f33179c35e29c80390992c958","73d77400060a06027d21c2000406037d25c20004062a"),
0x00323E3A:(7,"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9","0228ef00000a2a"),
0x00324441:(7,"9f03a1c4cfab457e28da7eb7dfc8950881e458be2c22f773d48bc15d76dc3c40","027b18c200042a"),
0x00324449:(7,"9f03a1c4cfab457e28da7eb7dfc8950881e458be2c22f773d48bc15d76dc3c40","027b18c200042a"),
0x00324451:(15,"5dd0586b0ab5d9853aad6e461f586ec232dd731664d19af0f9dbb5d23e69f110","02177d19c2000402157d1ac200042a"),
0x00324461:(6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49","73ee00000a7a"),
0x003245DA:(7,"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9","0228ef00000a2a"),
0x0032478B:(7,"c378542a12b73360475ddc0fcbc4f6a0f97ceb1f7fbad1b31c45e0b0824fa437","027b27c200042a"),
0x00324793:(7,"c378542a12b73360475ddc0fcbc4f6a0f97ceb1f7fbad1b31c45e0b0824fa437","027b27c200042a"),
0x0032479B:(15,"d27b961c83ff2de4635e3628410b7f1f6f24c2589a8f477ab150584622b0c3dc","02177d28c2000402157d29c200042a"),
0x003247AB:(6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49","73ee00000a7a"),
0x00323E44:(1521,"4a24846ef6fe5b1e729ee484cbdac32e5744eb183a9b23562fd7d865a8410f94",null),
0x003245E4:(411,"190881f0b3580bf1117c3f937040340778b36c472ddd6d9db01ae15286fa458a",null)
}
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]; n=struct.unpack_from("<H",pe,q+6)[0]; z=struct.unpack_from("<H",pe,q+20)[0]; s=q+24+z; out=[]
 for i in range(n):
  o=s+i*40; vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 if b&3!=3:raise E("header")
 fs=struct.unpack_from("<H",pe,o)[0]; h=(fs>>12)*4; n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 for rva,(n,sha,hx) in METHODS.items():
  c=body(pe,ss,rva)
  if len(c)!=n or hashlib.sha256(c).hexdigest()!=sha:raise E(hex(rva))
  if hx is not None and c.hex()!=hx:raise E(hex(rva)+" body")
 print("PROVE_MENU_SOUND_ASYNC_VOICE_FACTORIES_SUPPORT: PASS")
if __name__=="__main__":main()
