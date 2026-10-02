#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
G_RVA=0x003257B9; G_SHA="5de8447700a271c9b17ec8f23fe06668678a0e89c5a9b825074dc77fdc1763b4"
S_RVA=0x003257DD; S_SHA="32af8b52722443f3611991f370d4beb536ebfe0f4813884b525bcf4dbc8a0041"
G=bytes.fromhex("027be487000414280f00000a390c000000027be48700046fba0f000a2a22000000002a")
S=bytes.fromhex("027be487000414280f00000a390c000000027be4870004036fbb0f000a2a")
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];opt=struct.unpack_from("<H",pe,q+20)[0];so=q+24+opt;out=[]
 for i in range(n):
  o=so+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3!=2:raise E("tiny")
 return pe[o+1:o+1+(b>>2)]
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);g=body(pe,ss,G_RVA);s=body(pe,ss,S_RVA)
 if g!=G or hashlib.sha256(g).hexdigest()!=G_SHA:raise E("get_Pan")
 if s!=S or hashlib.sha256(s).hexdigest()!=S_SHA:raise E("set_Pan")
 for c,label,calltok in [(g,"get",0x0A000FBA),(s,"set",0x0A000FBB)]:
  if c[1]!=0x7B or struct.unpack_from("<I",c,2)[0]!=0x040087E4:raise E(label+" field gate")
  if c[7]!=0x28 or struct.unpack_from("<I",c,8)[0]!=0x0A00000F:raise E(label+" inequality")
  if c[18]!=0x7B or struct.unpack_from("<I",c,19)[0]!=0x040087E4:raise E(label+" source")
 if g[23]!=0x6F or struct.unpack_from("<I",g,24)[0]!=0x0A000FBA:raise E("get panStereo")
 if g[29:34]!=bytes.fromhex("2200000000"):raise E("get zero fallback")
 if s[23]!=0x03:raise E("set value")
 if s[24]!=0x6F or struct.unpack_from("<I",s,25)[0]!=0x0A000FBB:raise E("set panStereo")
 for tok in (0x060052D8,0x060052D9):
  t=struct.pack("<I",tok)
  for pre in (b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"):
   if pe.find(pre+t)>=0:raise E("direct inbound reference "+hex(tok))
 print("PROVE_U_AUDIO_PAN_ROUTING: PASS")
if __name__=="__main__":main()
