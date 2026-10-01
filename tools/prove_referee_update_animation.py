#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Update":(0x00307E94,415,"5d41c826c5bc4929960746b1b03abdd389b4911c89ec01a48fda0eba6e6c9e4a"),
 "InitRound":(0x00305AA0,244,"e49118b8c0107b96e5bcca09a2cd24853191f05c685c858415a176cac7ba3bc2")
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Update"]
 tok(c,0x0001,0x7B,0x040062BA,"isAnmPause")
 br(c,0x0006,0x39,0x000C,"pause false branch")
 if c[0x000B]!=0x2A:raise E("pause return")
 tok(c,0x000D,0x7B,0x040062BF,"reqAnmInit gate")
 br(c,0x0012,0x39,0x008C,"request-init skip")
 tok(c,0x0018,0x7E,0x04007CF6,"SkillDataMan.inst")
 tok(c,0x001E,0x7B,0x040062B5,"SkillID")
 tok(c,0x0023,0x6F,0x06005264,"GetSkillData_Standard")
 tok(c,0x0028,0x7D,0x040062B0,"CurrentSkill")
 if c[0x002D:0x002F]!=bytes([0x02,0x16]):raise E("CurrentAnmIdx zero")
 tok(c,0x002F,0x7D,0x040062B1,"CurrentAnmIdx")
 if c[0x0034:0x0036]!=bytes([0x02,0x17]):raise E("isAnmBoot one")
 tok(c,0x0036,0x7D,0x040062BD,"isAnmBoot")
 if c[0x003B:0x003D]!=bytes([0x02,0x15]):raise E("currentFormIdx -1")
 tok(c,0x003D,0x7D,0x040062B3,"currentFormIdx init")
 tok(c,0x0044,0x7B,0x040062B0,"CurrentSkill anmType source")
 tok(c,0x0049,0x7B,0x04007C53,"SkillData.anmType")
 tok(c,0x004E,0x7D,0x040062B6,"Referee.anmType")
 if c[0x0053:0x0055]!=bytes([0x02,0x16]):raise E("duration zero")
 tok(c,0x0055,0x7D,0x040062B2,"FormDispDuration init")
 tok(c,0x005B,0x7B,0x040062B0,"CurrentSkill anmData source")
 tok(c,0x0060,0x7B,0x04007C7A,"anmData")
 tok(c,0x0066,0x7B,0x040062B1,"CurrentAnmIdx load")
 if c[0x006B]!=0x9A:raise E("anmData element")
 tok(c,0x006F,0x7B,0x04007C97,"terrainColType")
 tok(c,0x0074,0x7D,0x040062A8,"TerrainColType")
 tok(c,0x007B,0x7B,0x04007C9E,"anmEndState")
 tok(c,0x0080,0x7D,0x040062A9,"AnimeEnd")
 if c[0x0085:0x0087]!=bytes([0x02,0x16]):raise E("reqAnmInit zero")
 tok(c,0x0087,0x7D,0x040062BF,"reqAnmInit clear")
 tok(c,0x008D,0x7B,0x040062B0,"shared CurrentSkill")
 tok(c,0x0092,0x7B,0x04007C7A,"shared anmData")
 tok(c,0x0098,0x7B,0x040062B1,"shared CurrentAnmIdx")
 if c[0x009D]!=0x9A:raise E("shared anmData element")
 tok(c,0x00A0,0x7B,0x040062B2,"duration gate")
 br(c,0x00A6,0x3D,0x00C5,"duration positive")
 tok(c,0x00AC,0x7B,0x040062B3,"form index reset check")
 tok(c,0x00B2,0x7B,0x04007C93,"formNum")
 br(c,0x00B9,0x3F,0x00C5,"form index still in range")
 if c[0x00BE:0x00C0]!=bytes([0x02,0x15]):raise E("form index reset -1")
 tok(c,0x00C0,0x7D,0x040062B3,"currentFormIdx reset")
 tok(c,0x00C6,0x7B,0x040062B2,"duration acquisition gate")
 br(c,0x00CB,0x3A,0x0190,"nonzero duration tail")
 if c[0x00D0:0x00D2]!=bytes([0x02,0x25]):raise E("form index increment dup")
 tok(c,0x00D2,0x7B,0x040062B3,"form index increment load")
 if c[0x00D7:0x00D9]!=bytes([0x17,0x58]):raise E("form index +1")
 tok(c,0x00D9,0x7D,0x040062B3,"form index increment store")
 tok(c,0x00DF,0x28,0x06005098,"GetCurrentFormDispInfo #1")
 tok(c,0x00EB,0x7B,0x04007CDC,"dispFrm loop test")
 br(c,0x00F0,0x39,0x00FA,"zero dispFrm retry")
 br(c,0x00F5,0x38,0x0114,"nonzero dispFrm accept")
 tok(c,0x00FC,0x7B,0x040062B3,"retry form index load")
 if c[0x0101:0x0103]!=bytes([0x17,0x58]):raise E("retry form index +1")
 tok(c,0x0103,0x7D,0x040062B3,"retry form index store")
 tok(c,0x0109,0x28,0x06005098,"GetCurrentFormDispInfo retry")
 br(c,0x010F,0x38,0x00EA,"retry loop back")
 tok(c,0x0116,0x7B,0x04007CDC,"accepted dispFrm")
 tok(c,0x011B,0x7D,0x040062B2,"FormDispDuration accepted")
 tok(c,0x0121,0x7C,0x04007CD8,"centerPos x address")
 tok(c,0x0126,0x7B,0x0A000059,"centerPos.x")
 tok(c,0x012D,0x7C,0x04007CD8,"centerPos y address")
 tok(c,0x0132,0x7B,0x0A00005A,"centerPos.y")
 if c[0x0137]!=0x65:raise E("centerPos.y negation")
 tok(c,0x013A,0x7B,0x040062A3,"PlDir")
 if c[0x013F]!=0x19:raise E("raw PlDir 3")
 br(c,0x0140,0x3F,0x0148,"PlDir < 3")
 if c[0x0145:0x0148]!=bytes([0x08,0x65,0x0C]):raise E("x negation")
 tok(c,0x0149,0x7C,0x040062A0,"PlPos x address")
 tok(c,0x014F,0x7B,0x0A000009,"PlPos.x load")
 tok(c,0x0156,0x7D,0x0A000009,"PlPos.x store")
 tok(c,0x015C,0x7C,0x040062A0,"PlPos y address")
 tok(c,0x0162,0x7B,0x0A00000A,"PlPos.y load")
 tok(c,0x0169,0x7D,0x0A00000A,"PlPos.y store")
 tok(c,0x0170,0x7B,0x04007CE6,"flags")
 tok(c,0x0175,0x7D,0x040062AA,"FormRev")
 tok(c,0x017B,0x7B,0x04007CE2,"seID gate")
 br(c,0x0180,0x39,0x0190,"seID zero skip")
 tok(c,0x0186,0x7B,0x04007CE2,"seID call value")
 tok(c,0x018B,0x28,0x06004971,"FACT-0064 PlayRefereeSE")
 if c[0x0190:0x0192]!=bytes([0x02,0x25]):raise E("tail dup")
 tok(c,0x0192,0x7B,0x040062B2,"duration tail load")
 if c[0x0197:0x0199]!=bytes([0x17,0x59]):raise E("duration -1")
 tok(c,0x0199,0x7D,0x040062B2,"duration tail store")
 if c[0x019E]!=0x2A:raise E("ret")
 tok(cs["InitRound"],0x00C9,0x28,0x06005097,"FACT-0069 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Update"][2]},"fact_0069_bridge":"0x00C9","fact_0064_sound_call":"0x018B"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_UPDATE_ANIMATION: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_UPDATE_ANIMATION: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
