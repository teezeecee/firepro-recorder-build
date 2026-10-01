#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={'Core':(0x00322B90,122,'56ce94a2d961f8cb774c95924d1cab7a28ed7dc521501dc72ace69c7ce39c162'),'Caller':(0x00321504,374,'4c90d23ad41281c6f3411dd71c82635d6b56e0a15c80f80d2abf775639f9a4f9')}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for x in iter(lambda:f.read(1<<20),b''):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from('<I',pe,0x3c)[0];n=struct.unpack_from('<H',pe,q+6)[0];z=struct.unpack_from('<H',pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E('rva')
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from('<H',pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from('<I',c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from('<i',c,o+1)[0]!=t:raise E(l)
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from('<f',c,o+1)[0]!=struct.unpack('<f',struct.pack('<f',v))[0]:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E('dll')
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+' body')
  cs[n]=c
 c=cs['Core']
 tok(c,0x0000,0x7E,0x040086FE,'clip list #1');br(c,0x0005,0x3A,0x000B,'clip list exists')
 if c[0x000A]!=0x2A:raise E('null list ret')
 if c[0x000B:0x000D]!=bytes([0x02,0x16]):raise E('snd_no >=0 args');br(c,0x000D,0x3F,0x001A,'negative')
 if c[0x0012:0x0015]!=bytes([0x02,0x1F,0x6D]):raise E('snd_no <109 args');br(c,0x0015,0x3F,0x001B,'upper')
 if c[0x001A]!=0x2A:raise E('range ret')
 tok(c,0x001B,0x7E,0x040086FE,'clip list #2')
 if c[0x0020:0x0022]!=bytes([0x02,0x9A]):raise E('clip index')
 if c[0x0022]!=0x14:raise E('ldnull')
 tok(c,0x0023,0x28,0x0A000006,'Object.op_Equality');br(c,0x0028,0x39,0x002E,'clip nonnull')
 if c[0x002D]!=0x2A:raise E('null clip ret')
 tok(c,0x002E,0x7E,0x040086EE,'Volume_Se')
 if c[0x0033:0x0036]!=bytes([0x03,0x5A,0x0A]):raise E('volume product')
 f32(c,0x0037,0.0,'zero');br(c,0x003C,0x41,0x0042,'bge.un lower')
 if c[0x0041]!=0x2A:raise E('lower ret')
 f32(c,0x0043,1.0,'one compare');br(c,0x0048,0x43,0x0053,'ble.un upper')
 f32(c,0x004D,1.0,'one cap')
 tok(c,0x0053,0x7E,0x040086EB,'audioSrcInfo')
 if c[0x0058:0x005B]!=bytes([0x18,0x9A,0x0B]):raise E('audioSrcInfo[2]')
 tok(c,0x005C,0x7B,0x0400874C,'sRefAudio #1');tok(c,0x0062,0x6F,0x0A0002A2,'set_volume')
 tok(c,0x0068,0x7B,0x0400874C,'sRefAudio #2');tok(c,0x006D,0x7E,0x040086FE,'clip list #3')
 if c[0x0072:0x0074]!=bytes([0x02,0x9A]):raise E('clip index #2')
 tok(c,0x0074,0x6F,0x0A000FA6,'PlayOneShot')
 if c[0x0079]!=0x2A:raise E('ret')
 tok(cs['Caller'],0x0170,0x28,0x060052A8,'FACT-0060 caller')
 return {'dll_sha256':DLL_SHA,'method':{'code_size':len(c),'code_sha256':M['Core'][2]},'caller':'FACT-0060'}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--out');x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_MENU_SOUND_MANAGER_PLAY_MATCH_SE: PASS');return 0
 except (OSError,ValueError,E) as e:
  print('PROVE_MENU_SOUND_MANAGER_PLAY_MATCH_SE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
