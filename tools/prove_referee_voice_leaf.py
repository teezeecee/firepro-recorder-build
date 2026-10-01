#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x00322C58,122,"6168083a2b8e7ff12b16c44ba759062f611c24ac73de637c5461485234e65b74"),
 "Caller":(0x003216E4,82,"c96840b83bb1f8795fc6e881c61a725201424c4dec3ff5188b932e16e3f1f745")
}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 tok(c,0x0000,0x7E,0x040086FF,"clip list #1")
 br(c,0x0005,0x3A,0x000B,"clip list exists")
 if c[0x000A]!=0x2A:raise E("null list return")
 if c[0x000B:0x000D]!=bytes([0x02,0x16]):raise E("vid >=0 args")
 br(c,0x000D,0x3F,0x001A,"negative vid return")
 if c[0x0012:0x0015]!=bytes([0x02,0x1F,0x18]):raise E("vid <24 args")
 br(c,0x0015,0x3F,0x001B,"vid <24")
 if c[0x001A]!=0x2A:raise E("vid range return")
 tok(c,0x001B,0x7E,0x040086FF,"clip list #2")
 if c[0x0020:0x0023]!=bytes([0x02,0x9A,0x14]):raise E("clip element/null")
 tok(c,0x0023,0x28,0x0A000006,"Object.op_Equality")
 br(c,0x0028,0x39,0x002E,"non-null clip")
 if c[0x002D]!=0x2A:raise E("null clip return")
 tok(c,0x002E,0x7E,0x040086EF,"Volume_Voice")
 if c[0x0033:0x0036]!=bytes([0x03,0x5A,0x0A]):raise E("volume multiply/store")
 if c[0x0036]!=0x06:raise E("volume local")
 f32(c,0x0037,0.0,"volume zero")
 br(c,0x003C,0x41,0x0042,"bge.un zero")
 if c[0x0041]!=0x2A:raise E("negative volume return")
 if c[0x0042]!=0x06:raise E("volume local upper")
 f32(c,0x0043,1.0,"volume one compare")
 br(c,0x0048,0x43,0x0053,"ble.un one")
 f32(c,0x004D,1.0,"volume clamp one")
 if c[0x0052]!=0x0A:raise E("volume clamp store")
 tok(c,0x0053,0x7E,0x040086EB,"audioSrcInfo #1")
 if c[0x0058:0x005B]!=bytes([0x1A,0x9A,0x0B]):raise E("audioSrcInfo[4]")
 if c[0x005B]!=0x07:raise E("source local #1")
 tok(c,0x005C,0x7B,0x0400874C,"sRefAudio #1")
 if c[0x0061]!=0x06:raise E("set_volume local")
 tok(c,0x0062,0x6F,0x0A0002A2,"AudioSource.set_volume")
 if c[0x0067]!=0x07:raise E("source local #2")
 tok(c,0x0068,0x7B,0x0400874C,"sRefAudio #2")
 tok(c,0x006D,0x7E,0x040086FF,"clip list #3")
 if c[0x0072:0x0074]!=bytes([0x02,0x9A]):raise E("clip element play")
 tok(c,0x0074,0x6F,0x0A000FA6,"AudioSource.PlayOneShot")
 if c[0x0079]!=0x2A:raise E("ret")
 c=cs["Caller"]
 if c[0x0046]!=0x03:raise E("FACT-0076 vid")
 f32(c,0x0047,1.0,"FACT-0076 fixed volume")
 tok(c,0x004C,0x28,0x060052A9,"FACT-0076 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(cs["Leaf"]),"code_sha256":M["Leaf"][2]},"valid_vid_range":[0,23],"source_index":4}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_VOICE_LEAF: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_VOICE_LEAF: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
