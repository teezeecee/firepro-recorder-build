#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Voice":(0x003216E4,82,"c96840b83bb1f8795fc6e881c61a725201424c4dec3ff5188b932e16e3f1f745"),
 "FightUI":(0x002B40A6,13,"4f1688f5e78f6692ef931ec6a1337cb88f04f099e3ec938be0f9d15b2c9fd65e"),
 "Caller":(0x00306394,100,"fba8e1eb077d2800274abf6f40345ed6768347f753aedaf9ccb023b2a24ea530")
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
 c=cs["Voice"]
 tok(c,0x0000,0x28,0x06004907,"MatchMain.GetInst")
 if c[0x0005]!=0x0A:raise E("stloc0")
 if c[0x0006]!=0x06:raise E("ldloc0")
 tok(c,0x0007,0x7B,0x04005752,"isFastForwardMatch")
 br(c,0x000C,0x39,0x002F,"fast-forward false dispatch")
 tok(c,0x0011,0x28,0x06004A70,"Fade.GetInst")
 tok(c,0x0016,0x6F,0x06004A7D,"FACT-0059 Fade.IsFadeFinish")
 br(c,0x001B,0x39,0x002F,"fade false dispatch")
 if c[0x0020]!=0x06:raise E("ldloc0 frame")
 tok(c,0x0021,0x7B,0x04005738,"MchFrameCnt")
 if c[0x0026:0x0029]!=bytes([0x1F,0x14,0x5E]):raise E("unsigned modulo 20")
 br(c,0x0029,0x39,0x002F,"remainder zero dispatch")
 if c[0x002E]!=0x2A:raise E("suppressed return")
 tok(c,0x002F,0x28,0x060050B2,"FACT-0065 RefereeMan.GetInst")
 tok(c,0x0034,0x6F,0x060050B6,"FACT-0065 GetRefereeObj")
 if c[0x0039]!=0x0B or c[0x003A]!=0x07:raise E("referee local")
 tok(c,0x003B,0x28,0x0A00002A,"referee op_Implicit")
 br(c,0x0040,0x3A,0x0046,"referee true")
 if c[0x0045]!=0x2A:raise E("no referee return")
 if c[0x0046]!=0x03:raise E("vid arg")
 f32(c,0x0047,1.0,"voice volume")
 tok(c,0x004C,0x28,0x060052A9,"Menu_SoundManager.Play_RefereeVoice")
 if c[0x0051]!=0x2A:raise E("voice ret")
 c=cs["FightUI"]
 if c[0x0000]!=0x02:raise E("Show_Fight this")
 tok(c,0x0001,0x7B,0x0400589B,"gameObj_Fight")
 if c[0x0006]!=0x03:raise E("Show_Fight sw")
 tok(c,0x0007,0x6F,0x0A000103,"GameObject.SetActive")
 if c[0x000C]!=0x2A:raise E("Show_Fight ret")
 c=cs["Caller"]
 if c[0x0052]!=0x16:raise E("FACT-0075 voice raw0")
 tok(c,0x0053,0x6F,0x06005279,"FACT-0075 PlayRefereeVoice")
 if c[0x005D]!=0x17:raise E("FACT-0075 fight raw1")
 tok(c,0x005E,0x6F,0x060049F4,"FACT-0075 Show_Fight")
 return {"dll_sha256":DLL_SHA,"methods":{"PlayRefereeVoice":M["Voice"][2],"Show_Fight":M["FightUI"][2]},"fact_0075_bridge":["0x0053","0x005E"]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_FIGHT_PRESENTATION: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_FIGHT_PRESENTATION: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
