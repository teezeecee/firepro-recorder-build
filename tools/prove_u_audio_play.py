#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325A80
SIZE=564
CODE_SHA="25cfa99ab6e97f650b4e517fa419b12acb018df2aab2933a87b40953a7084a26"
EH_HEX="4134000000000000a40100001c000000c001000006000000c2000001000000002a000000fb010000250200000e000000d2000001"
EH_SHA="f8df63a73e467352a3ef02ab450c1b90afb6379833275bb04e844ee0a95cd802"
CALLER_RVA=0x00323130
CALLER_SHA="e84b8a91478acffadf8ee5f39f17855e421d0cf1b4d482f97dfbb53700440a5a"
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
 if b&3==2:return {"offset":o,"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"offset":o,"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];cc=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=7 or m["local_sig"]!=0x11001220:raise E("header")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 tok(c,0x0001,0x7B,0x040087E9,"State #1")
 br(c,0x0007,0x3B,0x0233,"State raw1 return")
 tok(c,0x000D,0x7B,0x040087E9,"State #2")
 br(c,0x0013,0x40,0x0023,"State raw2 split")
 tok(c,0x0019,0x28,0x060052E9,"Pause")
 tok(c,0x0025,0x7D,0x040087E9,"State=1")
 tok(c,0x002C,0x7D,0x040087EB,"SongDone=false")
 tok(c,0x0033,0x7D,0x040087EC,"flare_SongEnd=false")
 tok(c,0x0039,0x28,0x060052D0,"FACT-0138 get_UAudio #1")
 tok(c,0x003F,0x7B,0x040087E6,"targetFile")
 tok(c,0x0044,0x7D,0x0A000FC1,"backend targetFile")
 tok(c,0x004A,0x7B,0x040087E4,"myAudioSource #1")
 tok(c,0x004F,0x6F,0x0A0007A0,"get_clip #1")
 tok(c,0x0055,0x28,0x0A000006,"Object equality")
 tok(c,0x0060,0x28,0x060052D0,"FACT-0138 get_UAudio #2")
 tok(c,0x0065,0x6F,0x0A000FC5,"LoadMainOutputStream")
 if c[0x0070:0x0072]!=bytes([0xFE,0x06]) or struct.unpack_from("<I",c,0x0072)[0]!=0x060052E8:raise E("Song_Stream_Loop ldftn")
 tok(c,0x0076,0x73,0x0A000FC6,"PCMReaderCallback ctor")
 tok(c,0x0082,0x28,0x0A000150,"File.OpenRead")
 tok(c,0x0099,0x6F,0x0A0009F1,"Stream.Dispose")
 tok(c,0x00A0,0x73,0x0A000FC7,"ReadFullyStream ctor")
 tok(c,0x00B1,0x7D,0x0A000FC8,"stream_CanSeek")
 tok(c,0x00C8,0x73,0x0A000FC9,"MpegFile ctor")
 tok(c,0x00D1,0x28,0x0A000FCA,"Nullable HasValue #1")
 tok(c,0x00DD,0x28,0x0A000FCB,"Nullable GetValueOrDefault")
 tok(c,0x00E2,0x7E,0x0A000FBD,"TimeSpan.Zero #1")
 tok(c,0x00E7,0x28,0x0A000FCC,"TimeSpan equality")
 tok(c,0x00FB,0x6F,0x0A000FCD,"ReadSamples")
 tok(c,0x0104,0x7D,0x040087EE,"playbackDevice")
 tok(c,0x010A,0x28,0x060052D0,"FACT-0138 get_UAudio #3")
 tok(c,0x010F,0x6F,0x0A000FAF,"SongLength")
 tok(c,0x0138,0x72,0x7008F3DA,"uAudio_song")
 tok(c,0x0141,0x6F,0x0A000FCE,"WaveFormat #1")
 tok(c,0x0146,0x6F,0x0A000FCF,"Channels")
 tok(c,0x014D,0x6F,0x0A000FCE,"WaveFormat #2")
 tok(c,0x0152,0x6F,0x0A000FD0,"SampleRate")
 tok(c,0x0159,0x28,0x0A000FD1,"AudioClip.Create")
 tok(c,0x015E,0x6F,0x0A00079B,"set_clip #1")
 tok(c,0x016A,0x6F,0x0A00079C,"set_loop")
 tok(c,0x0176,0x6F,0x0A000FD2,"set_timeSamples")
 tok(c,0x017D,0x28,0x0A000FCA,"Nullable HasValue #2")
 tok(c,0x0188,0x7E,0x0A000FBD,"TimeSpan.Zero #2")
 tok(c,0x018D,0x28,0x060052D7,"set_CurrentTime zero")
 tok(c,0x019A,0x28,0x0A000FD3,"Nullable.Value")
 tok(c,0x019F,0x28,0x060052D7,"set_CurrentTime value")
 tok(c,0x01A5,0x28,0x060052CB,"FACT-0127 get_sendPlaybackState #1")
 tok(c,0x01B0,0x28,0x060052CB,"FACT-0127 get_sendPlaybackState #2")
 tok(c,0x01B6,0x6F,0x0A000FC4,"callback Invoke")
 tok(c,0x01D2,0x6F,0x0A00079B,"set_clip null")
 tok(c,0x01E2,0x6F,0x0A0007A0,"get_clip #2")
 tok(c,0x01E8,0x28,0x0A00000F,"Object inequality")
 tok(c,0x01F8,0x6F,0x0A000CAE,"get_isPlaying")
 tok(c,0x0208,0x6F,0x0A0002A3,"AudioSource.Play")
 tok(c,0x020F,0x7D,0x040087EA,"updateTime=true")
 tok(c,0x021B,0x7D,0x040087E9,"State=0 normal")
 tok(c,0x0229,0x7D,0x040087E9,"State=0 catch")
 if c[0x0233]!=0x2A:raise E("ret")
 sec=(m["offset"]+m["header"]+len(c)+3)&~3
 eh=pe[sec:sec+52]
 if eh.hex()!=EH_HEX or hashlib.sha256(eh).hexdigest()!=EH_SHA:raise E("EH")
 for off in (0x00F6,0x01AD):tok(cc,off,0x6F,0x060052E7,"FACT-0133 caller")
 print("PROVE_U_AUDIO_PLAY: PASS")
if __name__=="__main__":main()
