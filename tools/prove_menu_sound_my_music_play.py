#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00323130
SIZE=481
CODE_SHA="e84b8a91478acffadf8ee5f39f17855e421d0cf1b4d482f97dfbb53700440a5a"
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
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0x11001213:raise E("header")
 if c[0:6]!=bytes([0x16,0x0B,0x03,0x1F,0x20,0x59]):raise E("local false/switch normalize")
 if c[0x0006]!=0x45 or struct.unpack_from("<I",c,0x0007)[0]!=4:raise E("switch")
 base=0x001B
 tg=[base+struct.unpack_from("<i",c,0x000B+i*4)[0] for i in range(4)]
 if tg!=[0x0020,0x005F,0x0116,0x0020]:raise E("switch targets")
 br(c,0x001B,0x38,0x01CD,"switch default")
 # progress branch
 tok(c,0x0021,0x7E,0x04008706,"progress file")
 tok(c,0x0026,0x28,0x060052B7,"check progress")
 br(c,0x002B,0x3A,0x003C,"progress valid")
 tok(c,0x0030,0x7E,0x0A000025,"String.Empty progress")
 tok(c,0x0035,0x80,0x04008706,"clear progress")
 if c[0x003A:0x003C]!=bytes([0x16,0x2A]):raise E("progress false")
 tok(c,0x003C,0x7E,0x04003903,"root progress")
 tok(c,0x0041,0x7E,0x04008706,"progress file #2")
 tok(c,0x0046,0x28,0x0A000012,"concat progress")
 tok(c,0x004B,0x80,0x04008707,"selected name progress")
 tok(c,0x0050,0x7E,0x040086F1,"progress volume")
 tok(c,0x0055,0x80,0x04008708,"selected volume progress")
 br(c,0x005A,0x38,0x01CD,"progress tail")
 # admission start
 tok(c,0x0060,0x7E,0x04008705,"admission file")
 tok(c,0x0065,0x28,0x060052B7,"check admission")
 br(c,0x006A,0x3A,0x007B,"admission valid")
 tok(c,0x006F,0x7E,0x0A000025,"String.Empty admission")
 tok(c,0x0074,0x80,0x04008705,"clear admission")
 if c[0x0079:0x007B]!=bytes([0x16,0x2A]):raise E("admission false")
 tok(c,0x007B,0x7E,0x04003903,"root admission")
 tok(c,0x0080,0x7E,0x04008705,"admission file #2")
 tok(c,0x0085,0x28,0x0A000012,"concat admission")
 tok(c,0x008A,0x80,0x04008707,"selected name admission")
 tok(c,0x008F,0x7E,0x040086F2,"admission volume")
 tok(c,0x0094,0x80,0x04008708,"selected volume admission")
 tok(c,0x0099,0x7E,0x04008707,"extension name admission")
 tok(c,0x009E,0x28,0x0A000BC1,"GetExtension admission")
 tok(c,0x00A3,0x6F,0x0A0002C0,"ToLower admission")
 if c[0x00A8]!=0x0A:raise E("extension local")
 if c[0x00A9]!=0x06:raise E("extension load")
 tok(c,0x00AA,0x72,0x7005186D,".mp3 admission")
 tok(c,0x00AF,0x28,0x0A00002F,"string equality admission")
 br(c,0x00B4,0x39,0x0111,"not mp3 admission")
 # direct uAudio first copy
 tok(c,0x00B9,0x7E,0x04008709,"uAudio gate admission")
 if c[0x00BE]!=0x14:raise E("null admission")
 tok(c,0x00BF,0x28,0x0A000006,"Object equality admission")
 br(c,0x00C4,0x39,0x00D9,"uAudio exists admission")
 if c[0x00C9]!=0x02:raise E("this gameObject admission")
 tok(c,0x00CA,0x28,0x0A000028,"get_gameObject admission")
 tok(c,0x00CF,0x6F,0x2B0003E2,"AddComponent uAudio admission")
 tok(c,0x00D4,0x80,0x04008709,"store uAudio admission")
 tok(c,0x00D9,0x7E,0x04008709,"LoadFile receiver admission")
 tok(c,0x00DE,0x7E,0x04008707,"LoadFile path admission")
 tok(c,0x00E3,0x6F,0x060052E4,"LoadFile admission")
 tok(c,0x00E8,0x7E,0x04008709,"Play receiver admission")
 if c[0x00ED:0x00EF]!=bytes([0x12,0x02]):raise E("local2 address admission")
 if c[0x00EF:0x00F1]!=bytes([0xFE,0x15]) or struct.unpack_from("<I",c,0x00F1)[0]!=0x1B0002D5:raise E("nullable init admission")
 if c[0x00F5]!=0x08:raise E("local2 admission")
 tok(c,0x00F6,0x6F,0x060052E7,"Play admission")
 tok(c,0x00FB,0x7E,0x04008709,"volume receiver admission")
 tok(c,0x0100,0x7E,0x04008708,"selected volume admission load")
 tok(c,0x0105,0x6F,0x060052E0,"ChangeCurrentVolume admission")
 if c[0x010A:0x010C]!=bytes([0x17,0x0B]):raise E("local1 true admission")
 br(c,0x010C,0x38,0x01CD,"admission direct tail")
 br(c,0x0111,0x38,0x01CD,"admission nonmp3 tail")
 # match check/path
 tok(c,0x0117,0x7E,0x04008704,"match file")
 tok(c,0x011C,0x28,0x060052B7,"check match")
 br(c,0x0121,0x3A,0x0132,"match valid")
 tok(c,0x0126,0x7E,0x0A000025,"String.Empty match")
 tok(c,0x012B,0x80,0x04008704,"clear match")
 if c[0x0130:0x0132]!=bytes([0x16,0x2A]):raise E("match false")
 tok(c,0x0132,0x7E,0x04003903,"root match")
 tok(c,0x0137,0x7E,0x04008704,"match file #2")
 tok(c,0x013C,0x28,0x0A000012,"concat match")
 tok(c,0x0141,0x80,0x04008707,"selected name match")
 tok(c,0x0146,0x7E,0x040086F3,"match volume")
 tok(c,0x014B,0x80,0x04008708,"selected volume match")
 tok(c,0x0150,0x7E,0x04008707,"extension name match")
 tok(c,0x0155,0x28,0x0A000BC1,"GetExtension match")
 tok(c,0x015A,0x6F,0x0A0002C0,"ToLower match")
 if c[0x015F:0x0161]!=bytes([0x0A,0x06]):raise E("extension local match")
 tok(c,0x0161,0x72,0x7005186D,".mp3 match")
 tok(c,0x0166,0x28,0x0A00002F,"string equality match")
 br(c,0x016B,0x39,0x01C8,"not mp3 match")
 # second uAudio copy
 tok(c,0x0170,0x7E,0x04008709,"uAudio gate match")
 if c[0x0175]!=0x14:raise E("null match")
 tok(c,0x0176,0x28,0x0A000006,"Object equality match")
 br(c,0x017B,0x39,0x0190,"uAudio exists match")
 if c[0x0180]!=0x02:raise E("this gameObject match")
 tok(c,0x0181,0x28,0x0A000028,"get_gameObject match")
 tok(c,0x0186,0x6F,0x2B0003E2,"AddComponent uAudio match")
 tok(c,0x018B,0x80,0x04008709,"store uAudio match")
 tok(c,0x0190,0x7E,0x04008709,"LoadFile receiver match")
 tok(c,0x0195,0x7E,0x04008707,"LoadFile path match")
 tok(c,0x019A,0x6F,0x060052E4,"LoadFile match")
 tok(c,0x019F,0x7E,0x04008709,"Play receiver match")
 if c[0x01A4:0x01A6]!=bytes([0x12,0x02]):raise E("local2 address match")
 if c[0x01A6:0x01A8]!=bytes([0xFE,0x15]) or struct.unpack_from("<I",c,0x01A8)[0]!=0x1B0002D5:raise E("nullable init match")
 if c[0x01AC]!=0x08:raise E("local2 match")
 tok(c,0x01AD,0x6F,0x060052E7,"Play match")
 tok(c,0x01B2,0x7E,0x04008709,"volume receiver match")
 tok(c,0x01B7,0x7E,0x04008708,"selected volume match load")
 tok(c,0x01BC,0x6F,0x060052E0,"ChangeCurrentVolume match")
 if c[0x01C1:0x01C3]!=bytes([0x17,0x0B]):raise E("local1 true match")
 br(c,0x01C3,0x38,0x01CD,"match direct tail")
 br(c,0x01C8,0x38,0x01CD,"match nonmp3 tail")
 # shared tail
 if c[0x01CD]!=0x07:raise E("local1 tail")
 br(c,0x01CE,0x3A,0x01DF,"direct path skip coroutine")
 if c[0x01D3]!=0x02:raise E("this coroutine")
 tok(c,0x01D4,0x72,0x7008EBBE,"MyMusic_Play_Co")
 tok(c,0x01D9,0x28,0x0A0000C4,"StartCoroutine string")
 if c[0x01DE:0x01E1]!=bytes([0x26,0x17,0x2A]):raise E("tail return true")
 print("PROVE_MENU_SOUND_MY_MUSIC_PLAY: PASS")
if __name__=="__main__":main()
