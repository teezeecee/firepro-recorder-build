#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325898
SIZE=203
CODE_SHA="f5518241de99069e054067f93d7d8145a91d461a4a5b8b78e01b5e8c364f5e26"
BODY=bytes.fromhex("027bea8700043933000000027be98700041740270000000228d65200060b120128820d000a6b0a027be5870004390c000000027be5870004066fc00f000a027bec870004391400000002167dec8700040228e652000602167dec870004027be8870004396200000002167de887000402167deb87000402167dec870004027be38700047ebd0f000a6fb90f000a0228e6520006027be487000414280600000a39170000007286ea0870286206000a0c02086f4c00002b7de4870004021203fe15d502001b0928e75200062a")
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];opt=struct.unpack_from("<H",pe,q+20)[0];so=q+24+opt;out=[]
 for i in range(n):
  o=so+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def locate(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise E("rva")
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);o=locate(ss,RVA);fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4
 if (fs&0x0FFF)!=0x0013 or h!=12 or struct.unpack_from("<H",pe,o+2)[0]!=2 or struct.unpack_from("<I",pe,o+8)[0]!=0x1100121F:raise E("header")
 if struct.unpack_from("<I",pe,o+4)[0]!=SIZE:raise E("size")
 c=pe[o+h:o+h+SIZE]
 if c!=BODY or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 tok(c,0x0001,0x7B,0x040087EA,"updateTime"); br(c,0x0006,0x39,0x003E,"updateTime false")
 tok(c,0x000C,0x7B,0x040087E9,"State"); 
 if c[0x0011]!=0x17:raise E("raw state 1")
 br(c,0x0012,0x40,0x003E,"state != 1")
 tok(c,0x0018,0x28,0x060052D6,"FACT-0128 get_CurrentTime")
 if c[0x001D]!=0x0B or c[0x001E:0x0020]!=bytes([0x12,0x01]):raise E("TimeSpan local")
 tok(c,0x0020,0x28,0x0A000D82,"TotalSeconds")
 if c[0x0025:0x0027]!=bytes([0x6B,0x0A]):raise E("conv.r4/stloc0")
 tok(c,0x0028,0x7B,0x040087E5,"time callback gate"); br(c,0x002D,0x39,0x003E,"callback null")
 tok(c,0x0033,0x7B,0x040087E5,"time callback"); 
 if c[0x0038]!=0x06:raise E("callback arg")
 tok(c,0x0039,0x6F,0x0A000FC0,"Action<Single>.Invoke")
 tok(c,0x003F,0x7B,0x040087EC,"flare gate"); br(c,0x0044,0x39,0x005D,"flare false")
 if c[0x0049:0x004B]!=bytes([0x02,0x16]):raise E("flare clear #1 args")
 tok(c,0x004B,0x7D,0x040087EC,"flare clear #1")
 tok(c,0x0051,0x28,0x060052E6,"FACT-0126 SongEnd #1")
 if c[0x0056:0x0058]!=bytes([0x02,0x16]):raise E("flare clear #2 args")
 tok(c,0x0058,0x7D,0x040087EC,"flare clear #2")
 tok(c,0x005E,0x7B,0x040087E8,"source destroy gate"); br(c,0x0063,0x39,0x00CA,"source destroy false")
 if c[0x0068:0x006A]!=bytes([0x02,0x16]):raise E("source destroy clear args")
 tok(c,0x006A,0x7D,0x040087E8,"source destroy clear")
 if c[0x006F:0x0071]!=bytes([0x02,0x16]):raise E("SongDone clear args")
 tok(c,0x0071,0x7D,0x040087EB,"SongDone clear")
 if c[0x0076:0x0078]!=bytes([0x02,0x16]):raise E("flare clear #3 args")
 tok(c,0x0078,0x7D,0x040087EC,"flare clear #3")
 tok(c,0x007E,0x7B,0x040087E3,"backend")
 tok(c,0x0083,0x7E,0x0A000FBD,"TimeSpan.Zero")
 tok(c,0x0088,0x6F,0x0A000FB9,"backend set_CurrentTime")
 tok(c,0x008E,0x28,0x060052E6,"FACT-0126 SongEnd #2")
 tok(c,0x0094,0x7B,0x040087E4,"audio source gate")
 if c[0x0099]!=0x14:raise E("null")
 tok(c,0x009A,0x28,0x0A000006,"Object equality"); br(c,0x009F,0x39,0x00BB,"source nonnull")
 tok(c,0x00A4,0x72,0x7008EA86,"Sound_Manager")
 tok(c,0x00A9,0x28,0x0A000662,"GameObject.Find")
 if c[0x00AE]!=0x0C or c[0x00AF:0x00B1]!=bytes([0x02,0x08]):raise E("GameObject local")
 tok(c,0x00B1,0x6F,0x2B00004C,"AddComponent AudioSource")
 tok(c,0x00B6,0x7D,0x040087E4,"audio source store")
 if c[0x00BB:0x00BE]!=bytes([0x02,0x12,0x03]):raise E("nullable local address")
 if c[0x00BE:0x00C0]!=bytes([0xFE,0x15]) or struct.unpack_from("<I",c,0x00C0)[0]!=0x1B0002D5:raise E("Nullable<TimeSpan> initobj")
 if c[0x00C4]!=0x09:raise E("nullable local load")
 tok(c,0x00C5,0x28,0x060052E7,"FACT-0140 Play")
 if c[0x00CA]!=0x2A:raise E("ret")
 t=struct.pack("<I",0x060052E3)
 for pre in (b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"):
  if pe.find(pre+t)>=0:raise E("direct inbound Update reference")
 print("PROVE_U_AUDIO_UPDATE: PASS")
if __name__=="__main__":main()
