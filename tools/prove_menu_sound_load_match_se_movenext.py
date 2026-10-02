#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
MAIN_RVA=0x003238A0; MAIN_SHA="f80edfba4bbae0a9f8538fe6abf28795445ad07b7558bd988c5f9fec8b79eed0"
SMALL={
0x00323A3C:(7,"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9"),
0x00323A44:(19,"c464156a84c67e9523c5fc1d5c43ef0acd8dffd406b94f26963b58f17742069d"),
0x00321A4C:(22,"374fd489b8e5ddd8431fbfedf3f2441f6c2ae47f54ae83bada355263b3af9fe0"),
0x00323A58:(7,"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9"),
0x00323AFF:(7,"8d21a6bcd74e1487bfbdb7c7b166ba89153a64c43d55c03916b2da7b9cb212a5"),
0x00323B07:(7,"8d21a6bcd74e1487bfbdb7c7b166ba89153a64c43d55c03916b2da7b9cb212a5"),
0x00323B0F:(15,"69f03bb2a7db86d01e301011c3a8286cb9e8033ff1c21e6a48ef97bfc1d77fc1"),
0x00323B1F:(6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49")
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
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,MAIN_RVA)
 if len(c)!=361 or hashlib.sha256(c).hexdigest()!=MAIN_SHA:raise E("MoveNext")
 for rva,(size,sha) in SMALL.items():
  b=body(pe,ss,rva)
  if len(b)!=size or hashlib.sha256(b).hexdigest()!=sha:raise E(hex(rva))
 tok(c,0x0001,0x7B,0x0400C1F4,"PC load")
 tok(c,0x0009,0x7D,0x0400C1F4,"PC minus1")
 tok(c,0x0021,0x7E,0x040086FE,"clip list gate")
 if c[0x0030:0x0032]!=bytes([0x1F,0x6D]):raise E("raw109")
 tok(c,0x0032,0x8D,0x01000012,"AudioClip array")
 tok(c,0x0037,0x80,0x040086FE,"clip list store")
 tok(c,0x003D,0x73,0x06007514,"closure ctor")
 tok(c,0x004E,0x7D,0x0400C271,"closure backref")
 tok(c,0x005A,0x7D,0x0400C270,"i zero")
 tok(c,0x0070,0x28,0x06005273,"FACT-0062")
 tok(c,0x0080,0x7B,0x04008664,"fileName")
 tok(c,0x0090,0x7E,0x0A000025,"String.Empty")
 if c[0x00A5:0x00A8]!=bytes([0x1F,0x67,0x3F]):raise E("raw103 split")
 tok(c,0x00AD,0x72,0x7008F366,"environment")
 tok(c,0x00CD,0x72,0x7008F38C,"base")
 if c[0x0100:0x0102]!=bytes([0xFE,0x06]) or struct.unpack_from("<I",c,0x0102)[0]!=0x06007515:raise E("callback ldftn")
 tok(c,0x010B,0x28,0x06005285,"LoadAsyncAsset")
 tok(c,0x0110,0x28,0x0A00035A,"StartCoroutine")
 tok(c,0x0115,0x7D,0x0400C1F2,"current")
 tok(c,0x0124,0x7D,0x0400C1F4,"PC1")
 tok(c,0x0141,0x7D,0x0400C270,"i increment store")
 tok(c,0x0159,0x80,0x040086FC,"load end true")
 if c[0x0165:0x0169]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("returns")
 cb=body(pe,ss,0x00323A44)
 tok(cb,0x0000,0x7E,0x040086FE,"callback list")
 tok(cb,0x0006,0x7B,0x0400C270,"callback i")
 la=body(pe,ss,0x00321A4C)
 tok(la,0x0000,0x73,0x060074BF,"LoadAsync ctor")
 tok(la,0x0008,0x7D,0x0400C1F6,"path store")
 tok(la,0x000F,0x7D,0x0400C1F8,"callback store")
 print("PROVE_MENU_SOUND_LOAD_MATCH_SE_MOVENEXT: PASS")
if __name__=="__main__":main()
