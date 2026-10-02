#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M=[
 (0x00322FC0,21,"49e066c2b1ee1ab65086c2e443f5cb0f8cf3aa35b639aba7646ba87dc609e4c9",0x1100120B),
 (0x00322FE4,110,"4706c335f4923a712dae0e35d839c427459c3268d2fd380435d7bb9bcdca0ff1",0x11001211),
 (0x00323060,57,"0af8b0fc25dd48cd0572ac0c664bf58267f9ef3a3fcb6dae9e3eaaa76ab37bd8",0x11001212)]
CALLERS=[
 (0x001967B8,"2744708499e1e415118f63637c8974880de16b0826fb43a04d64a68293e351c3",0x0010,0x060052B2),
 (0x00381B50,"6207b3fa339666a90e0ddcdb16ba5b9d102dd0bac95e8c88bc40ded8cadd5e06",0x01E6,0x060052B2),
 (0x00382768,"c856b31998bcbb389c1c799d01effcad76efc1ece9a2156452ee3a005405ffa7",0x0172,0x060052B2),
 (0x00382AD8,"ca342bc58825286e79fbe4fb0e663188e0293bdbd05f9ababe620461ff7ed0ae",0x0243,0x060052B2),
 (0x00298E54,"4b48e06349f5cb97df7d0d66bc84a34b5fb7272b8f6fcb04dedc27ba92da8f5c",0x08E9,0x060052B3),
 (0x002AB3EC,"984f158c2da0fa72e67938d2970400e4e59fd96be8a32c0b256ca80109cc29ac",0x0195,0x060052B3),
 (0x002AB3EC,"984f158c2da0fa72e67938d2970400e4e59fd96be8a32c0b256ca80109cc29ac",0x03CA,0x060052B3),
 (0x002AD660,"2ae0da4a7e54fd7f3a74034bad7db65239cbcfedbf76d9d48ae767e7c0fff92a",0x007A,0x060052B3),
 (0x002AD660,"2ae0da4a7e54fd7f3a74034bad7db65239cbcfedbf76d9d48ae767e7c0fff92a",0x0218,0x060052B3),
 (0x00382F60,"a714b8cc124f30e9729f53d180e28326cd16c756e57ebec7c7438a06a3cb1050",0x0000,0x060052B3),
 (0x00219060,"4874a58e2203b400d9e4137bc39f57f5e702936bc71bb6f6b413a337f00ddc67",0x00A5,0x060052B4),
 (0x00219A04,"aed0809bad06e2322fa008401650ae9ed979d55243a8c4db751c5fd26a1edf0b",0x00AE,0x060052B4)]
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"code":pe[o+1:o+1+(b>>2)],"flags":2,"max_stack":8,"local_sig":0}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"code":pe[o+h:o+h+n],"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);bodies={}
 for rva,size,sha,ls in M:
  m=method(pe,ss,rva);c=m["code"];bodies[rva]=c
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E("body "+hex(rva))
  if m["flags"]!=0x0013 or m["max_stack"]!=3 or m["local_sig"]!=ls:raise E("header "+hex(rva))
 w=bodies[0x00322FC0]
 tok(w,0x0000,0x7E,0x040086EB,"w audioSrcInfo")
 tok(w,0x0005,0x7E,0x040086F5,"w audio_source_index")
 if w[0x000A:0x000D]!=bytes([0x19,0x58,0x9A]):raise E("w +3/select")
 tok(w,0x000F,0x6F,0x060052C4,"w Stop")
 if w[0x0014]!=0x2A:raise E("w ret")
 s=bodies[0x00322FE4]
 if s[0:2]!=bytes([0x16,0x0A]):raise E("StopSE i=0")
 br(s,0x0002,0x38,0x0030,"StopSE loop check")
 br(s,0x0008,0x3A,0x0012,"StopSE i0 test")
 br(s,0x000D,0x38,0x002C,"StopSE skip0")
 br(s,0x0014,0x40,0x001E,"StopSE i1 test")
 br(s,0x0019,0x38,0x002C,"StopSE skip1")
 tok(s,0x001E,0x7E,0x040086EB,"StopSE audioSrcInfo")
 tok(s,0x0027,0x6F,0x060052C4,"StopSE Stop")
 br(s,0x0032,0x3F,0x0007,"StopSE raw 0..7")
 tok(s,0x0038,0x80,0x040086F9,"fade cnt=0")
 tok(s,0x003E,0x80,0x040086FA,"fade frm=0")
 tok(s,0x004A,0x7E,0x040086ED,"lockTimes")
 if s[0x0050]!=0x22 or struct.unpack_from("<f",s,0x0051)[0]!=0.0 or s[0x0055]!=0xA0:raise E("lockTimes[j]=0f")
 tok(s,0x005B,0x7E,0x040086E8,"SystemSEFileList")
 br(s,0x0062,0x3F,0x004A,"lock loop")
 tok(s,0x0068,0x80,0x040086F5,"audio_source_index=0")
 if s[0x006D]!=0x2A:raise E("StopSE ret")
 y=bodies[0x00323060]
 tok(y,0x0000,0x7E,0x040086EB,"system audioSrcInfo")
 if y[0x0005:0x0008]!=bytes([0x17,0x9A,0x0A]):raise E("system slot1/local")
 tok(y,0x0009,0x6F,0x060052C4,"system Stop")
 tok(y,0x0015,0x7E,0x040086ED,"system lockTimes")
 if y[0x001B]!=0x22 or struct.unpack_from("<f",y,0x001C)[0]!=0.0 or y[0x0020]!=0xA0:raise E("system lock zero")
 tok(y,0x0026,0x7E,0x040086E8,"system list")
 br(y,0x002D,0x3F,0x0015,"system lock loop")
 tok(y,0x0033,0x80,0x040086F5,"system index zero")
 if y[0x0038]!=0x2A:raise E("system ret")
 for rva,sha,off,target in CALLERS:
  c=method(pe,ss,rva)["code"]
  if hashlib.sha256(c).hexdigest()!=sha:raise E("caller hash "+hex(rva))
  if c[off]!=0x28 or struct.unpack_from("<I",c,off+1)[0]!=target:raise E("caller direct ref "+hex(rva))
 print("PROVE_MENU_SOUND_STOP_RESET_FAMILY: PASS")
if __name__=="__main__":main()
