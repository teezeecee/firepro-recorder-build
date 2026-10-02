#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002DE53C
SIZE=272
CODE_SHA="827f27896099f2fabf61cc8659bb91cfd1ef7c2cccee142cd3e754ba3e577d8d"
FACT0015_RVA=0x002DB718
FACT0015_SHA="ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085"

class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"offset":o,"header":1,"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"offset":o,"header":h,"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];p=method(pe,ss,FACT0015_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=4 or m["local_sig"]!=0x11001063:raise E("header")
 if hashlib.sha256(p).hexdigest()!=FACT0015_SHA:raise E("FACT-0015 body")
 tok(c,0x0000,0x7E,0x0400576C,"MatchMain.inst #1")
 if c[0x0005]!=0x14:raise E("null #1")
 tok(c,0x0006,0x28,0x0A00000F,"Object inequality #1")
 br(c,0x000B,0x39,0x0041,"MatchMain null gate")
 tok(c,0x0010,0x7E,0x0400576C,"MatchMain.inst #2")
 tok(c,0x0015,0x7B,0x04005752,"isFastForwardMatch")
 br(c,0x001A,0x39,0x0041,"fast-forward gate")
 tok(c,0x001F,0x7E,0x0400591E,"Fade.inst")
 tok(c,0x0024,0x6F,0x06004A7D,"FACT-0059 IsFadeFinish")
 br(c,0x0029,0x39,0x0041,"fade gate")
 tok(c,0x002E,0x7E,0x0400576C,"MatchMain.inst #3")
 tok(c,0x0033,0x7B,0x04005738,"MchFrameCnt")
 if c[0x0038:0x003B]!=bytes([0x1F,0x14,0x5E]):raise E("raw unsigned modulo 20")
 br(c,0x003B,0x39,0x0041,"frame remainder")
 if c[0x0040]!=0x2A:raise E("throttle return")
 if c[0x0041]!=0x02:raise E("this animator request")
 tok(c,0x0042,0x7B,0x04005FA8,"animator")
 tok(c,0x0047,0x7B,0x04005ECF,"AnmReqType")
 if c[0x004C]!=0x17:raise E("raw AnmReqType 1")
 br(c,0x004D,0x3B,0x0053,"AnmReqType gate")
 if c[0x0052]!=0x2A:raise E("AnmReqType return")
 tok(c,0x0053,0x7E,0x040061FA,"PlayerMan.inst")
 if c[0x0058]!=0x02:raise E("this host player")
 tok(c,0x0059,0x7B,0x04005FA8,"animator host")
 tok(c,0x005E,0x7B,0x04005ED7,"AnmHostPlayer")
 tok(c,0x0063,0x6F,0x06005065,"FACT-0109 GetPlObj")
 if c[0x0068]!=0x0A:raise E("stloc0")
 if c[0x0069:0x006B]!=bytes([0x06,0x14]):raise E("player null setup")
 tok(c,0x006B,0x28,0x0A000006,"Object equality")
 br(c,0x0070,0x3A,0x008B,"player null return")
 if c[0x0075]!=0x02:raise E("this animator null")
 tok(c,0x0076,0x7B,0x04005FA8,"animator null test")
 br(c,0x007B,0x39,0x008B,"animator null return")
 if c[0x0080]!=0x06:raise E("local0 WresParam")
 tok(c,0x0081,0x7B,0x04005FB3,"WresParam test")
 br(c,0x0086,0x3A,0x008C,"WresParam non-null")
 if c[0x008B]!=0x2A:raise E("shared null return")
 if c[0x008C]!=0x06:raise E("skillVoice owner")
 tok(c,0x008D,0x7B,0x04005FB3,"WresParam skillVoice")
 tok(c,0x0092,0x7B,0x040010A8,"skillVoice")
 if c[0x0097]!=0x02:raise E("skill slot this")
 tok(c,0x0098,0x7B,0x04005FA8,"animator skill slot")
 tok(c,0x009D,0x7B,0x04005ED9,"SkillSlotID")
 if c[0x00A2:0x00A4]!=bytes([0x94,0x0B]):raise E("skillVoice index/local1")
 if c[0x00A4:0x00A6]!=bytes([0x07,0x16]):raise E("voice id lower gate")
 br(c,0x00A6,0x3C,0x00AC,"voice id signed >=0")
 if c[0x00AB]!=0x2A:raise E("negative voice return")
 if c[0x00AC]!=0x06:raise E("voice play PlIdx owner")
 tok(c,0x00AD,0x7B,0x04005FA6,"PlIdx")
 if c[0x00B2]!=0x07:raise E("voice play local1")
 if c[0x00B3:0x00B8]!=bytes.fromhex("220000803f"):raise E("voice play raw 1.0")
 tok(c,0x00B8,0x28,0x060052B1,"Play_WrestlerVoice")
 tok(c,0x00BD,0x7E,0x040054C9,"Audience.inst #1")
 if c[0x00C2]!=0x14:raise E("Audience null")
 tok(c,0x00C3,0x28,0x0A00000F,"Audience inequality")
 br(c,0x00C8,0x39,0x010F,"Audience null return")
 tok(c,0x00CD,0x7E,0x040011E6,"WrestlerVoiceInfoManager.inst")
 if c[0x00D2]!=0x06:raise E("voiceType WresParam owner")
 tok(c,0x00D3,0x7B,0x04005FB3,"WresParam voiceType")
 tok(c,0x00D8,0x7B,0x040010A1,"voiceType")
 if c[0x00DD:0x00DF]!=bytes([0x07,0x94]):raise E("voiceType index")
 if c[0x00DF]!=0x06:raise E("voiceID WresParam owner")
 tok(c,0x00E0,0x7B,0x04005FB3,"WresParam voiceID")
 tok(c,0x00E5,0x7B,0x040010A2,"voiceID")
 if c[0x00EA:0x00EC]!=bytes([0x07,0x94]):raise E("voiceID index")
 tok(c,0x00EC,0x6F,0x060011E8,"FACT-0183 GetWrestlerVoiceAttr")
 if c[0x00F1:0x00F3]!=bytes([0x0C,0x08]):raise E("local2 cheer")
 tok(c,0x00F3,0x7B,0x040011DC,"cheerVoice #1")
 if c[0x00F8]!=0x15:raise E("raw cheer -1")
 br(c,0x00F9,0x3B,0x010F,"cheer -1 return")
 tok(c,0x00FE,0x7E,0x040054C9,"Audience.inst #2")
 if c[0x0103]!=0x08:raise E("local2 cheer #2")
 tok(c,0x0104,0x7B,0x040011DC,"cheerVoice #2")
 if c[0x0109]!=0x1A:raise E("raw cheer level 4")
 tok(c,0x010A,0x6F,0x060047D9,"FACT-0079 PlayCheerVoice")
 if c[0x010F]!=0x2A:raise E("ret")
 tok(p,0x008E,0x6F,0x06004EB4,"FACT-0015 inbound caller")
 t=struct.pack("<I",0x06004EB4);hits=[];pos=0
 while True:
  i=pe.find(t,pos)
  if i<0:break
  hits.append(i);pos=i+1
 if len(hits)!=1 or pe[hits[0]-1]!=0x6F:raise E("direct reference uniqueness")
 print("PROVE_PLAYER_PLAY_WRESTLER_VOICE: PASS")
if __name__=="__main__":main()
