#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003254AC
SIZE=328
CODE_SHA="19dabb20d473fa3b479ae5e4d54dd67e44063fc7b40e2537738b472ce9dbeb98"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def locate(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise E("rva")
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def brs(c,o,op,target,l):
 if c[o]!=op or o+2+struct.unpack_from("<b",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);o=locate(ss,RVA);fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4
 if (fs&0x0FFF)!=0x0013 or h!=12 or struct.unpack_from("<H",pe,o+2)[0]!=4 or struct.unpack_from("<I",pe,o+8)[0]!=0x11000047:raise E("header")
 if struct.unpack_from("<I",pe,o+4)[0]!=SIZE:raise E("size")
 c=pe[o+h:o+h+SIZE]
 if hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 tok(c,0x0001,0x7B,0x0400C26F,"$PC load")
 tok(c,0x0009,0x7D,0x0400C26F,"$PC=-1")
 if c[0x000F]!=0x45 or struct.unpack_from("<I",c,0x0010)[0]!=3:raise E("switch")
 base=0x0020
 tg=[base+struct.unpack_from("<i",c,0x0014+4*i)[0] for i in range(3)]
 if tg!=[0x0025,0x006F,0x00B6]:raise E("switch targets")
 br(c,0x0020,0x38,0x0144,"default")
 tok(c,0x0026,0x72,0x7008EBDE,"file prefix")
 tok(c,0x002B,0x7E,0x04008707,"selected name")
 tok(c,0x0030,0x28,0x0A000012,"String.Concat")
 tok(c,0x0035,0x7D,0x0400C269,"url store")
 tok(c,0x003C,0x7B,0x0400C269,"url load")
 tok(c,0x0041,0x73,0x0A000FA7,"WWW ctor")
 tok(c,0x0046,0x7D,0x0400C26A,"WWW store")
 br(c,0x004B,0x38,0x006F,"WWW join")
 tok(c,0x0051,0x73,0x0A00064D,"WaitForEndOfFrame ctor #1")
 tok(c,0x0056,0x7D,0x0400C26D,"current #1")
 tok(c,0x005C,0x7B,0x0400C26E,"disposing #1")
 brs(c,0x0061,0x2D,0x006A,"disposing #1")
 tok(c,0x0065,0x7D,0x0400C26F,"PC=1")
 br(c,0x006A,0x38,0x0146,"yield1")
 tok(c,0x0070,0x7B,0x0400C26A,"WWW poll")
 tok(c,0x0075,0x6F,0x0A000FA8,"WWW isDone")
 br(c,0x007A,0x39,0x0050,"WWW not done")
 tok(c,0x0081,0x7B,0x0400C26A,"WWW GetAudioClip arg")
 if c[0x0086:0x0088]!=bytes([0x16,0x17]):raise E("GetAudioClip bool args")
 tok(c,0x0088,0x28,0x0A000FA9,"GetAudioClip")
 tok(c,0x008D,0x7D,0x0400C26B,"audioTrack store")
 br(c,0x0092,0x38,0x00B6,"load-state join")
 tok(c,0x0098,0x73,0x0A00064D,"WaitForEndOfFrame ctor #2")
 tok(c,0x009D,0x7D,0x0400C26D,"current #2")
 tok(c,0x00A3,0x7B,0x0400C26E,"disposing #2")
 brs(c,0x00A8,0x2D,0x00B1,"disposing #2")
 tok(c,0x00AC,0x7D,0x0400C26F,"PC=2")
 br(c,0x00B1,0x38,0x0146,"yield2")
 tok(c,0x00B7,0x7B,0x0400C26B,"audioTrack load")
 tok(c,0x00BC,0x6F,0x0A000FAA,"get_loadState")
 if c[0x00C1]!=0x17:raise E("raw loadState 1")
 br(c,0x00C2,0x3B,0x0097,"loadState raw1")
 tok(c,0x00C8,0x7E,0x040086EB,"audioSrcInfo array")
 if c[0x00CD:0x00CF]!=bytes([0x16,0x9A]):raise E("audioSrcInfo[0]")
 tok(c,0x00CF,0x7D,0x0400C26C,"s store")
 tok(c,0x00D5,0x7B,0x0400C26C,"s volume")
 tok(c,0x00DA,0x7B,0x0400874C,"source volume")
 tok(c,0x00DF,0x7E,0x04008708,"MyMusic_Volume")
 tok(c,0x00E4,0x6F,0x0A0002A2,"set_volume")
 tok(c,0x00EA,0x7B,0x0400C26C,"s clip")
 tok(c,0x00EF,0x7B,0x0400874C,"source clip")
 tok(c,0x00F5,0x7B,0x0400C26B,"audioTrack clip")
 tok(c,0x00FA,0x6F,0x0A00079B,"set_clip")
 tok(c,0x0100,0x7B,0x0400C26C,"s loop")
 tok(c,0x0105,0x7B,0x0400874C,"source loop")
 if c[0x010A]!=0x17:raise E("loop true")
 tok(c,0x010B,0x6F,0x0A00079C,"set_loop")
 tok(c,0x0111,0x7B,0x0400C26C,"s Play")
 tok(c,0x0116,0x7B,0x0400874C,"source Play")
 tok(c,0x011B,0x6F,0x0A0002A3,"Play")
 tok(c,0x0121,0x7B,0x0400C26C,"s fade frm")
 if c[0x0126]!=0x16:raise E("fadeOutFrm zero")
 tok(c,0x0127,0x7D,0x0400874E,"fadeOutFrm")
 tok(c,0x012D,0x7B,0x0400C26C,"s fade cnt")
 if c[0x0132]!=0x16:raise E("fadeOutCnt zero")
 tok(c,0x0133,0x7D,0x0400874D,"fadeOutCnt")
 br(c,0x0138,0x38,0x0144,"finish false")
 if c[0x013D:0x013F]!=bytes([0x02,0x15]):raise E("raw trailing PC=-1 args")
 tok(c,0x013F,0x7D,0x0400C26F,"trailing PC=-1")
 if c[0x0144:0x0148]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("returns")
 print("PROVE_MENU_SOUND_MY_MUSIC_PLAY_CO_MOVENEXT: PASS")
if __name__=="__main__":main()
