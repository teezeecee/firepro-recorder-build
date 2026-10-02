#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00324470
SIZE=311
CODE_SHA="b7cd1752de05dfc07cc79a9b416fd025358fd0f6d9041e7c03f72b564c054b64"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def locate(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise E("rva")
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def brs(c,o,op,target,l):
 if c[o]!=op or o+2+struct.unpack_from("<b",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);o=locate(ss,RVA);fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4
 if (fs&0x0FFF)!=0x0013 or h!=12 or struct.unpack_from("<H",pe,o+2)[0]!=4 or struct.unpack_from("<I",pe,o+8)[0]!=0x1100121A:raise E("header")
 if struct.unpack_from("<I",pe,o+4)[0]!=SIZE:raise E("size")
 c=pe[o+h:o+h+SIZE]
 if hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 tok(c,0x0001,0x7B,0x0400C220,"$PC load")
 tok(c,0x0009,0x7D,0x0400C220,"$PC=-1")
 if c[0x000F]!=0x45 or struct.unpack_from("<I",c,0x0010)[0]!=2:raise E("switch")
 base=0x001C
 tg=[base+struct.unpack_from("<i",c,0x0014+4*i)[0] for i in range(2)]
 if tg!=[0x0021,0x00D1]:raise E("switch targets")
 br(c,0x001C,0x38,0x0133,"default false")
 tok(c,0x0021,0x7E,0x040086FF,"clips gate")
 br(c,0x0026,0x39,0x0030,"clips null")
 br(c,0x002B,0x38,0x0133,"clips already loaded")
 if c[0x0030:0x0032]!=bytes([0x1F,0x18]):raise E("clip count 24")
 tok(c,0x0032,0x8D,0x01000012,"AudioClip[]")
 tok(c,0x0037,0x80,0x040086FF,"clips store")
 tok(c,0x003D,0x7E,0x0400866C,"RefereeVoiceDataNum")
 tok(c,0x0043,0x7B,0x0400C21B,"type")
 tok(c,0x0049,0x8D,0x01000190,"ResourceRequest[]")
 tok(c,0x004E,0x7D,0x0400C21C,"resReq store")
 tok(c,0x005A,0x7E,0x0400866D,"prefix array")
 tok(c,0x0060,0x7B,0x0400C21B,"type prefix")
 tok(c,0x0066,0x72,0x700082AA,"format string")
 tok(c,0x006C,0x8C,0x010000D7,"box Int32")
 tok(c,0x0071,0x28,0x0A00050B,"String.Format")
 tok(c,0x0076,0x28,0x0A000012,"String.Concat")
 tok(c,0x007D,0x7B,0x0400C21C,"resReq fill")
 tok(c,0x0084,0x28,0x0A000675,"Resources.LoadAsync")
 tok(c,0x0090,0x7B,0x0400C21C,"resReq length build")
 br(c,0x0097,0x3F,0x005A,"build loop")
 tok(c,0x009E,0x7D,0x0400C21D,"i=0")
 br(c,0x00A3,0x38,0x0119,"consume check")
 br(c,0x00A8,0x38,0x00D1,"consume poll")
 if c[0x00AD]!=0x02 or c[0x00AE]!=0x22 or struct.unpack_from("<f",c,0x00AF)[0]!=0.0:raise E("WaitForSeconds 0")
 tok(c,0x00B3,0x73,0x0A000679,"WaitForSeconds ctor")
 tok(c,0x00B8,0x7D,0x0400C21E,"$current")
 tok(c,0x00BE,0x7B,0x0400C21F,"$disposing")
 brs(c,0x00C3,0x2D,0x00CC,"disposing")
 tok(c,0x00C7,0x7D,0x0400C220,"$PC=1")
 br(c,0x00CC,0x38,0x0135,"yield true")
 tok(c,0x00D2,0x7B,0x0400C21C,"resReq poll")
 tok(c,0x00D8,0x7B,0x0400C21D,"i poll")
 tok(c,0x00DE,0x6F,0x0A000676,"get_isDone")
 br(c,0x00E3,0x39,0x00AD,"not done")
 tok(c,0x00E8,0x7E,0x040086FF,"clips asset store")
 tok(c,0x00EE,0x7B,0x0400C21D,"i asset")
 tok(c,0x00F4,0x7B,0x0400C21C,"resReq asset")
 tok(c,0x00FA,0x7B,0x0400C21D,"i request asset")
 tok(c,0x0100,0x6F,0x0A000677,"get_asset")
 tok(c,0x0105,0x75,0x01000012,"AudioClip cast")
 tok(c,0x010D,0x7B,0x0400C21D,"i increment")
 tok(c,0x0114,0x7D,0x0400C21D,"i store")
 tok(c,0x011A,0x7B,0x0400C21D,"i check")
 tok(c,0x0120,0x7B,0x0400C21C,"resReq length consume")
 br(c,0x0127,0x3F,0x00A8,"consume loop")
 tok(c,0x012E,0x7D,0x0400C220,"final PC=-1")
 if c[0x0133:0x0137]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("returns")
 print("PROVE_MENU_SOUND_LOAD_ASYNC_REFEREE_VOICE_MOVENEXT: PASS")
if __name__=="__main__":main()
