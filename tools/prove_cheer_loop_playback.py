#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Play":(0x00322DCC,158,"001cb4d3bd5417613100f8bfe639e04dda3482b57c57eb21ef6522ce30adfebe"),"SetVol":(0x00322EDC,76,"6f321c7c744fbfc0c24a57378d548aa080b210e4d264ec0cf63d9c9576338126"),"Caller":(0x0028FF68,276,"45701fac9b7e62ecbae949718859ea29a3dac586af0f7494c87b405de7262b4b")}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise E(l)
def shared(c,base_audio):
 tok(c,0x0030 if len(c)>100 else 0x0000,0x7E,0x040086F0,"Volume_Cheer")
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Play"]
 tok(c,0x0000,0x7E,0x04008701,"clip list #1");br(c,0x0005,0x3A,0x000B,"list exists")
 if c[0x000B:0x000D]!=bytes([0x02,0x16]):raise E("vid lower args")
 br(c,0x000D,0x3F,0x001A,"vid negative")
 if c[0x0012:0x0015]!=bytes([0x02,0x1F,0x2A]):raise E("vid upper args")
 br(c,0x0015,0x3F,0x001B,"vid <42")
 tok(c,0x001B,0x7E,0x04008701,"clip list #2");tok(c,0x0025,0x28,0x0A000006,"clip null equality");br(c,0x002A,0x39,0x0030,"clip nonnull")
 tok(c,0x0030,0x7E,0x040086F0,"Volume_Cheer play")
 f32(c,0x0039,0.0,"lower zero");br(c,0x003E,0x41,0x0049,"lower bge.un");f32(c,0x0043,0.0,"lower clamp")
 f32(c,0x004A,1.0,"upper one");br(c,0x004F,0x43,0x005A,"upper ble.un");f32(c,0x0054,1.0,"upper clamp")
 tok(c,0x005A,0x7E,0x040086EB,"audioSrcInfo play")
 if c[0x005F:0x0062]!=bytes([0x1D,0x9A,0x0C]):raise E("audioSrcInfo[7]")
 tok(c,0x0063,0x7B,0x0400874C,"sRefAudio play");tok(c,0x006A,0x28,0x0A00002A,"source truth");br(c,0x006F,0x39,0x009D,"source false")
 tok(c,0x0076,0x6F,0x0A0002A2,"set_volume");tok(c,0x007D,0x6F,0x0A00079B,"set_clip")
 if c[0x0082:0x0084]!=bytes([0x09,0x17]):raise E("set_loop args")
 tok(c,0x0084,0x6F,0x0A00079C,"set_loop");tok(c,0x008A,0x6F,0x0A0002A3,"Play")
 tok(c,0x0091,0x7D,0x0400874E,"fadeOutFrm zero");tok(c,0x0098,0x7D,0x0400874D,"fadeOutCnt zero")
 if c[0x009D]!=0x2A:raise E("play ret")
 c=cs["SetVol"]
 tok(c,0x0000,0x7E,0x040086F0,"Volume_Cheer setvol")
 f32(c,0x0009,0.0,"setvol lower zero");br(c,0x000E,0x41,0x0019,"setvol lower bge.un");f32(c,0x0013,0.0,"setvol lower clamp")
 f32(c,0x001A,1.0,"setvol upper one");br(c,0x001F,0x43,0x002A,"setvol upper ble.un");f32(c,0x0024,1.0,"setvol upper clamp")
 tok(c,0x002A,0x7E,0x040086EB,"audioSrcInfo setvol")
 if c[0x002F:0x0032]!=bytes([0x1D,0x9A,0x0B]):raise E("setvol audioSrcInfo[7]")
 tok(c,0x0033,0x7B,0x0400874C,"setvol sRefAudio");tok(c,0x003A,0x28,0x0A00002A,"setvol source truth");br(c,0x003F,0x39,0x004B,"setvol source false")
 tok(c,0x0046,0x6F,0x0A0002A2,"setvol call")
 if c[0x004B]!=0x2A:raise E("setvol ret")
 c=cs["Caller"];tok(c,0x00FA,0x28,0x060052AD,"FACT-0081 Play caller");tok(c,0x010E,0x28,0x060052B0,"FACT-0081 SetVol caller")
 return {"dll_sha256":DLL_SHA,"methods":{"Play":M["Play"][2],"SetVol":M["SetVol"][2]},"source_index":7}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_CHEER_LOOP_PLAYBACK: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_CHEER_LOOP_PLAYBACK: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
