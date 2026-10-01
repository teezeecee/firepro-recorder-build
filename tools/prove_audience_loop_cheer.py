#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Leaf":(0x0028FF68,276,"45701fac9b7e62ecbae949718859ea29a3dac586af0f7494c87b405de7262b4b"),
 "Caller":(0x0028FE43,50,"36b8ed39e946a670d66af8344565ee39ada17a831fb66a84935def5e66450dc0")
}
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 tok(c,0x0000,0x28,0x06004907,"MatchMain.GetInst")
 tok(c,0x0007,0x7B,0x04005752,"isFastForwardMatch")
 br(c,0x000C,0x39,0x002F,"fast false")
 tok(c,0x0011,0x28,0x06004A70,"Fade.GetInst");tok(c,0x0016,0x6F,0x06004A7D,"Fade.IsFadeFinish")
 br(c,0x001B,0x39,0x002F,"fade false")
 tok(c,0x0021,0x7B,0x04005738,"MchFrameCnt")
 if c[0x0026:0x0029]!=bytes([0x1F,0x14,0x5E]):raise E("mod20")
 br(c,0x0029,0x39,0x002F,"remainder zero")
 if c[0x002E]!=0x2A:raise E("throttle return")
 if c[0x002F:0x0032]!=bytes([0x03,0x17,0x3C]):raise E("nLevel lower compare")
 if struct.unpack_from("<i",c,0x0032)[0]+0x0036!=0x0039:raise E("lower branch")
 if c[0x0036:0x0039]!=bytes([0x17,0x10,0x01]):raise E("nLevel=1")
 if c[0x0039:0x003C]!=bytes([0x03,0x1A,0x3E]):raise E("nLevel upper compare")
 if struct.unpack_from("<i",c,0x003C)[0]+0x0040!=0x0043:raise E("upper branch")
 if c[0x0040:0x0043]!=bytes([0x1A,0x10,0x01]):raise E("nLevel=4")
 if c[0x0043:0x0045]!=bytes([0x03,0x02]):raise E("local level args")
 tok(c,0x0045,0x7B,0x040054CA,"CheerLevel_Total #1")
 if c[0x004A:0x004E]!=bytes([0x58,0x19,0x58,0x0B]):raise E("localLevel expression")
 f32(c,0x004E,0.3,"low init");f32(c,0x0054,1.0,"high init")
 tok(c,0x005B,0x7B,0x04005750,"AttendanceRate #1");f32(c,0x0060,0.0,"zero compare")
 br(c,0x0065,0x40,0x007B,"bne.un zero")
 f32(c,0x006A,0.0,"zero low");f32(c,0x0070,0.0,"zero high");br(c,0x0076,0x38,0x00A5,"zero join")
 f32(c,0x007C,1.0,"low one");tok(c,0x0082,0x7B,0x04005750,"AttendanceRate #2");f32(c,0x0088,0.1,"low factor")
 f32(c,0x0091,1.0,"high one");tok(c,0x0097,0x7B,0x04005750,"AttendanceRate #3");f32(c,0x009D,0.5,"high factor")
 f32(c,0x00AB,11.0,"level divisor");f32(c,0x00B7,1.0,"volume multiply one")
 if c[0x00BF:0x00C3]!=bytes([0x1F,0x28,0x13,0x05]):raise E("selected id init40")
 tok(c,0x00C4,0x7B,0x040054CA,"CheerLevel_Total #4")
 if c[0x00C9:0x00CB]!=bytes([0x17,0x3D]):raise E("level >1")
 if c[0x00CF:0x00D3]!=bytes([0x1F,0x27,0x13,0x05]):raise E("selected id39")
 tok(c,0x00D4,0x7B,0x040054CA,"CheerLevel_Total #5")
 if c[0x00D9:0x00DB]!=bytes([0x1A,0x3F]):raise E("level <4")
 if c[0x00DF:0x00E3]!=bytes([0x1F,0x29,0x13,0x05]):raise E("selected id41")
 br(c,0x00E4,0x3A,0x00F6,"force_play true")
 tok(c,0x00EC,0x7B,0x040054CD,"stored loop id")
 br(c,0x00F1,0x3B,0x010C,"same id")
 if c[0x00F6:0x00FA]!=bytes([0x11,0x05,0x11,0x04]):raise E("loop playback args")
 tok(c,0x00FA,0x28,0x060052AD,"Play_CheerVoice_Loop")
 tok(c,0x0102,0x7D,0x040054CD,"store loop id")
 br(c,0x0107,0x38,0x0113,"play join")
 if c[0x010C:0x010E]!=bytes([0x11,0x04]):raise E("volume-only arg")
 tok(c,0x010E,0x28,0x060052B0,"SetVol_CheerVoice_Loop")
 if c[0x0113]!=0x2A:raise E("ret")
 c=cs["Caller"]
 if c[0x0029:0x002C]!=bytes([0x02,0x16,0x16]):raise E("FACT-0079 caller args")
 tok(c,0x002C,0x28,0x060047DA,"FACT-0079 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(cs["Leaf"]),"code_sha256":M["Leaf"][2]},"raw_ids":[39,40,41]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_AUDIENCE_LOOP_CHEER: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_AUDIENCE_LOOP_CHEER: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
