#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00322750
SIZE=309
CODE_SHA="b8e1c3d745fe8e77062c61c6ed822cf58159f4de99e69e662c91b9646745eb2f"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 m=method(pe,sections(pe),RVA);c=m["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=3 or m["local_sig"]!=0x1100120A:raise E("header")
 tok(c,0x0000,0x7E,0x040086EB,"audioSrcInfo")
 if c[0x0005:0x0008]!=bytes([0x16,0x9A,0x0A]):raise E("slot0/local0")
 tok(c,0x0009,0x7B,0x0400874C,"sRefAudio")
 if c[0x000E]!=0x0B:raise E("local1")
 tok(c,0x000F,0x7E,0x04008703,"g_ProgressBGM_Continue")
 br(c,0x0014,0x39,0x0030,"continue false")
 tok(c,0x001A,0x28,0x0A00002A,"Object.op_Implicit")
 br(c,0x001F,0x39,0x0030,"source false")
 tok(c,0x0025,0x6F,0x0A000CAE,"get_isPlaying")
 br(c,0x002A,0x39,0x0030,"not playing")
 if c[0x002F]!=0x2A:raise E("early ret")
 tok(c,0x0030,0x28,0x060052A4,"FACT-0123 StopBGM")
 tok(c,0x0035,0x7E,0x040086F4,"audioClipInfo null gate")
 br(c,0x003A,0x39,0x005E,"audioClipInfo null")
 if c[0x003F:0x0042]!=bytes([0x02,0x1F,0x27]):raise E("bgm_type/raw39")
 br(c,0x0042,0x3C,0x005E,"upper bound")
 tok(c,0x0047,0x7E,0x040086F4,"audioClipInfo lookup")
 if c[0x004C:0x004E]!=bytes([0x02,0x9A]):raise E("audioClipInfo[bgm_type]")
 tok(c,0x004E,0x7B,0x0400874B,"audioClip field")
 if c[0x0053]!=0x14:raise E("null clip")
 tok(c,0x0054,0x28,0x0A000006,"Object.op_Equality")
 br(c,0x0059,0x39,0x005F,"clip nonnull")
 if c[0x005E]!=0x2A:raise E("clip-null ret")
 tok(c,0x005F,0x28,0x0600527C,"FACT-0112 get__instance")
 if c[0x0064:0x0066]!=bytes([0x02,0x03]):raise E("MyMusic args")
 tok(c,0x0066,0x6F,0x060052B8,"MyMusic_Play")
 br(c,0x006B,0x39,0x0071,"MyMusic false")
 if c[0x0070]!=0x2A:raise E("MyMusic true ret")
 if c[0x0071]!=0x02:raise E("bgmKind arg")
 tok(c,0x0072,0x80,0x040086F8,"bgmKind")
 if c[0x0077:0x007B]!=bytes([0x02,0x1F,0x20,0x59]):raise E("switch normalize")
 if c[0x007B]!=0x45 or struct.unpack_from("<I",c,0x007C)[0]!=4:raise E("switch")
 base=0x0090
 tg=[base+struct.unpack_from("<i",c,0x0080+i*4)[0] for i in range(4)]
 if tg!=[0x0095,0x00A5,0x00B5,0x00C5]:raise E("volume switch targets")
 br(c,0x0090,0x38,0x00D5,"volume default")
 for off,field in [(0x0096,0x040086F1),(0x00A6,0x040086F2),(0x00B6,0x040086F3),(0x00C6,0x040086F1)]:
  tok(c,off,0x7E,field,"volume field")
 for off in (0x009B,0x00AB,0x00BB,0x00CB,0x00DF):tok(c,off,0x6F,0x0A0002A2,"set_volume")
 if c[0x00D5:0x00D9]!=bytes([0x1F,0x20,0x10,0x00]):raise E("default rewrite bgm_type=32")
 if c[0x00D9]!=0x07 or c[0x00DA]!=0x22 or struct.unpack_from("<f",c,0x00DB)[0]!=1.0:raise E("default volume1")
 if c[0x00E9:0x00EB]!=bytes([0x03,0x17]):raise E("PLAY_TYPE raw1")
 br(c,0x00EB,0x40,0x0122,"PLAY_TYPE split")
 if c[0x00F0]!=0x07:raise E("source set_clip")
 tok(c,0x00F1,0x7E,0x040086F4,"clip array")
 if c[0x00F6:0x00F8]!=bytes([0x02,0x9A]):raise E("clip index")
 tok(c,0x00F8,0x7B,0x0400874B,"clip field #2")
 tok(c,0x00FD,0x6F,0x0A00079B,"set_clip")
 tok(c,0x0103,0x6F,0x0A0002A3,"Play")
 if c[0x0108:0x010A]!=bytes([0x07,0x17]):raise E("loop true")
 tok(c,0x010A,0x6F,0x0A00079C,"set_loop")
 if c[0x010F:0x0111]!=bytes([0x06,0x16]):raise E("fadeOutFrm zero")
 tok(c,0x0111,0x7D,0x0400874E,"fadeOutFrm")
 if c[0x0116:0x0118]!=bytes([0x06,0x16]):raise E("fadeOutCnt zero")
 tok(c,0x0118,0x7D,0x0400874D,"fadeOutCnt")
 br(c,0x011D,0x38,0x0134,"play join")
 if c[0x0122]!=0x07:raise E("oneshot source")
 tok(c,0x0123,0x7E,0x040086F4,"oneshot array")
 if c[0x0128:0x012A]!=bytes([0x02,0x9A]):raise E("oneshot index")
 tok(c,0x012A,0x7B,0x0400874B,"oneshot clip")
 tok(c,0x012F,0x6F,0x0A000FA6,"PlayOneShot")
 if c[0x0134]!=0x2A:raise E("ret")
 print("PROVE_MENU_SOUND_PLAY_BGM: PASS")
if __name__=="__main__":main()
