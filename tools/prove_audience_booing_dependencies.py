#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "TensionDown":(0x0028FE43,50,"36b8ed39e946a670d66af8344565ee39ada17a831fb66a84935def5e66450dc0"),
 "PlayCheerVoice":(0x0028FEB0,171,"ae89176689967732040134fd4991d756cbe400831f634051ea2aacea57113a6b"),
 "Caller":(0x00308FB4,90,"b7e8964816ea334e17fdf26aeb44a9789251e264d1bcc2eedc1fbd0fcc3ea42d")
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
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["TensionDown"]
 if c[0:2]!=bytes([0x02,0x25]):raise E("TensionDown receiver")
 tok(c,0x0002,0x7B,0x040054CB,"CheerLevel_Base read #1")
 if c[0x0007:0x0009]!=bytes([0x17,0x59]):raise E("decrement one")
 tok(c,0x0009,0x7D,0x040054CB,"CheerLevel_Base write #1")
 tok(c,0x000F,0x7B,0x040054CB,"CheerLevel_Base read #2")
 if c[0x0014:0x0016]!=bytes([0x1F,0xFC]):raise E("raw -4 compare")
 br(c,0x0016,0x3C,0x0023,"signed bge -4")
 if c[0x001B:0x001E]!=bytes([0x02,0x1F,0xFC]):raise E("raw -4 clamp")
 tok(c,0x001E,0x7D,0x040054CB,"CheerLevel_Base write #2")
 if c[0x0023]!=0x02:raise E("CalcCheerLevel receiver")
 tok(c,0x0024,0x28,0x060047E0,"CalcCheerLevel")
 if c[0x0029:0x002C]!=bytes([0x02,0x16,0x16]):raise E("PlayLoopCheerVoice raw args")
 tok(c,0x002C,0x28,0x060047DA,"PlayLoopCheerVoice")
 if c[0x0031]!=0x2A:raise E("TensionDown ret")
 c=cs["PlayCheerVoice"]
 tok(c,0x0000,0x28,0x06004907,"MatchMain.GetInst")
 if c[0x0005:0x0007]!=bytes([0x0A,0x06]):raise E("MatchMain local")
 tok(c,0x0007,0x7B,0x04005752,"isFastForwardMatch")
 br(c,0x000C,0x39,0x002F,"fast false")
 tok(c,0x0011,0x28,0x06004A70,"Fade.GetInst")
 tok(c,0x0016,0x6F,0x06004A7D,"Fade.IsFadeFinish")
 br(c,0x001B,0x39,0x002F,"fade false")
 tok(c,0x0021,0x7B,0x04005738,"MchFrameCnt")
 if c[0x0026:0x0029]!=bytes([0x1F,0x14,0x5E]):raise E("unsigned modulo20")
 br(c,0x0029,0x39,0x002F,"remainder zero")
 if c[0x002E]!=0x2A:raise E("throttle return")
 if c[0x002F:0x0031]!=bytes([0x04,0x0B]):raise E("nLevel local")
 f32(c,0x0031,0.5,"low init"); 
 if c[0x0036]!=0x0C:raise E("low stloc")
 f32(c,0x0037,1.0,"high init")
 if c[0x003C]!=0x0D:raise E("high stloc")
 if c[0x003D]!=0x06:raise E("attendance receiver #1")
 tok(c,0x003E,0x7B,0x04005750,"AttendanceRate #1")
 f32(c,0x0043,0.0,"attendance zero")
 br(c,0x0048,0x40,0x005E,"bne.un zero")
 f32(c,0x004D,0.0,"zero low"); 
 if c[0x0052]!=0x0C:raise E("zero low store")
 f32(c,0x0053,0.0,"zero high")
 if c[0x0058]!=0x0D:raise E("zero high store")
 br(c,0x0059,0x38,0x0088,"zero join")
 if c[0x005E]!=0x08:raise E("low load")
 f32(c,0x005F,1.0,"one low")
 if c[0x0064]!=0x06:raise E("attendance receiver #2")
 tok(c,0x0065,0x7B,0x04005750,"AttendanceRate #2")
 if c[0x006A]!=0x59:raise E("one-attendance low")
 f32(c,0x006B,0.2,"low factor")
 if c[0x0070:0x0073]!=bytes([0x5A,0x59,0x0C]):raise E("low arithmetic")
 if c[0x0073]!=0x09:raise E("high load")
 f32(c,0x0074,1.0,"one high")
 if c[0x0079]!=0x06:raise E("attendance receiver #3")
 tok(c,0x007A,0x7B,0x04005750,"AttendanceRate #3")
 if c[0x007F]!=0x59:raise E("one-attendance high")
 f32(c,0x0080,0.5,"high factor")
 if c[0x0085:0x0088]!=bytes([0x5A,0x59,0x0D]):raise E("high arithmetic")
 if c[0x0088:0x008E]!=bytes([0x08,0x09,0x08,0x59,0x07,0x6B]):raise E("final expression prefix")
 f32(c,0x008E,4.0,"nLevel divisor")
 if c[0x0093:0x0098]!=bytes([0x5B,0x5A,0x58,0x13,0x04]):raise E("final expression store")
 if c[0x0098:0x009A]!=bytes([0x11,0x04]):raise E("local4 load")
 f32(c,0x009A,1.0,"final multiply one")
 if c[0x009F:0x00A2]!=bytes([0x5A,0x13,0x04]):raise E("final multiply store")
 if c[0x00A2:0x00A5]!=bytes([0x03,0x11,0x04]):raise E("dispatch args")
 tok(c,0x00A5,0x28,0x060052AC,"Play_CheerVoice_OneShot")
 if c[0x00AA]!=0x2A:raise E("PlayCheerVoice ret")
 c=cs["Caller"]
 if c[0x0035:0x0038]!=bytes([0x1F,0x09,0x16]):raise E("FACT-0078 raw 9,0")
 tok(c,0x0038,0x6F,0x060047D9,"FACT-0078 PlayCheerVoice")
 tok(c,0x0054,0x6F,0x060047D7,"FACT-0078 TensionDown")
 return {"dll_sha256":DLL_SHA,"methods":{"TensionDown":M["TensionDown"][2],"PlayCheerVoice":M["PlayCheerVoice"][2]},"fact_0078_bridge":["0x0038","0x0054"]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_AUDIENCE_BOOING_DEPENDENCIES: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_AUDIENCE_BOOING_DEPENDENCIES: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
