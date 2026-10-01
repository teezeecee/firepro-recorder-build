#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Init":(0x003059EC,167,"e19f6d9ac4f9301e31c9e58d32ed267743c5bd5e6c44ae16a1aa04e4e02f8e24"),
 "Req":(0x00307E2C,92,"460f863df8f05cabe8f18840b94a8b6a3bdd22505263f3baf51edd0b900be7b6"),
 "Main":(0x002AD188,523,"2cf73d3b9e4f7c5d0e3e3bf24708c219538bab0e1dcac04dc076329b4002c98d"),
 "Cp":(0x002AE534,303,"c5fc6e292c2adf300eeda5ad44d8c2e0d0650a59e63eadf41213ea81f90e1d6d")
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
 c=cs["Init"]
 if c[0:3]!=bytes([0x02,0x14,0x02]):raise E("Init ctor args")
 tok(c,0x0003,0x28,0x0A000028,"Component.get_gameObject")
 tok(c,0x0008,0x73,0x06001F1E,"FormRenderer ctor")
 tok(c,0x000D,0x7D,0x040062A1,"FormRen store")
 tok(c,0x0014,0x7D,0x040062A2,"Referee formSize")
 tok(c,0x001A,0x7B,0x040062A1,"FormRen read")
 tok(c,0x0020,0x7D,0x04002734,"FormRenderer formSize")
 br(c,0x0027,0x38,0x006E,"loop initial branch")
 tok(c,0x002D,0x7B,0x040062A1,"loop FormRen")
 tok(c,0x0032,0x7B,0x0400273A,"target partsScale")
 tok(c,0x0039,0x7B,0x04000D5F,"source partsScale")
 if c[0x003E:0x0041]!=bytes([0x06,0x98,0xA0]):raise E("copy partsScale index")
 tok(c,0x0042,0x7B,0x040062A1,"FormRen compare")
 tok(c,0x0047,0x7B,0x0400273A,"partsScale compare")
 if c[0x004C:0x004E]!=bytes([0x06,0x98]):raise E("compare element")
 f32(c,0x004E,0.0,"compare zero")
 br(c,0x0053,0x41,0x006A,"bge.un normalization")
 tok(c,0x0059,0x7B,0x040062A1,"FormRen replacement")
 tok(c,0x005E,0x7B,0x0400273A,"partsScale replacement")
 if c[0x0063]!=0x06:raise E("replacement index")
 f32(c,0x0064,1.0,"replacement one")
 if c[0x0069]!=0xA0:raise E("replacement stelem.r4")
 if c[0x006E:0x0071]!=bytes([0x06,0x1F,0x09]):raise E("loop <9 args")
 br(c,0x0071,0x3F,0x002C,"loop blt")
 tok(c,0x0077,0x7C,0x040062A0,"PlPos x")
 f32(c,0x007C,0.0,"PlPos x value");tok(c,0x0081,0x7D,0x0A000009,"Vector3.x")
 tok(c,0x0087,0x7C,0x040062A0,"PlPos y")
 f32(c,0x008C,0.0,"PlPos y value");tok(c,0x0091,0x7D,0x0A00000A,"Vector3.y")
 tok(c,0x0097,0x7C,0x040062A0,"PlPos z")
 f32(c,0x009C,1.0,"PlPos z value");tok(c,0x00A1,0x7D,0x0A000056,"Vector3.z")
 if c[0x00A6]!=0x2A:raise E("Init return")
 c=cs["Req"]
 writes=[
  (0x0002,0x040062B5),(0x0009,0x040062B4),(0x0010,0x040062CE),(0x0017,0x040062BF),
  (0x001E,0x040062B8),(0x0025,0x040062B9),(0x002C,0x040062BA),(0x0033,0x040062BB),
  (0x003A,0x040062BC),(0x0041,0x040062BD),(0x0048,0x040062BE),(0x004F,0x040062C0),(0x0056,0x040062C1)]
 for off,t in writes:tok(c,off,0x7D,t,"Req field "+hex(t))
 if c[0:2]!=bytes([0x02,0x03]):raise E("SkillID=an")
 if c[0x0015:0x0017]!=bytes([0x02,0x17]):raise E("reqAnmInit one")
 for off in [0x0007,0x000E,0x001C,0x0023,0x002A,0x0031,0x0038,0x003F,0x0046,0x004D,0x0054]:
  if c[off:off+2]!=bytes([0x02,0x16]):raise E("Req zero prefix "+hex(off))
 if c[0x005B]!=0x2A:raise E("Req return")
 tok(cs["Main"],0x0156,0x6F,0x06005079,"FACT-0067 Main Init")
 tok(cs["Main"],0x01FB,0x6F,0x06005096,"FACT-0067 Main Req")
 tok(cs["Cp"],0x00EB,0x6F,0x06005079,"FACT-0067 Cp Init")
 tok(cs["Cp"],0x010B,0x6F,0x06005096,"FACT-0067 Cp Req")
 return {"dll_sha256":DLL_SHA,"methods":{"Init":M["Init"][2],"ReqRefereeAnm":M["Req"][2]},"parts_scale_indices":[0,8],"fact_0067_bridges":4}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_INIT_REQUEST: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_INIT_REQUEST: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
