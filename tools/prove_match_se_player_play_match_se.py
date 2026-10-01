#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={'Core':(0x00321504,374,'4c90d23ad41281c6f3411dd71c82635d6b56e0a15c80f80d2abf775639f9a4f9'),'Wrapper':(0x002B0AE4,95,'20b2b0b4629e94a1522ac997f16d94062fd0e3ad779184615939a1ee3a794aae')}
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
 if c[0:3]!=bytes([0x03,0x1F,0x6D]):raise E('seid<109 args')
 br(c,0x0003,0x3F,0x0009,'seid<109')
 if c[0x0008]!=0x2A:raise E('seid>=109 ret')
 tok(c,0x0009,0x28,0x0600505D,'PlayerMan.GetInst')
 if c[0x000E]!=0x05:raise E('pl_idx arg')
 tok(c,0x000F,0x6F,0x06005065,'PlayerMan.GetPlObj')
 if c[0x0015:0x0017]!=bytes([0x03,0x16]):raise E('seid>=0 args')
 br(c,0x0017,0x3C,0x001D,'seid>=0')
 if c[0x001C]!=0x2A:raise E('negative seid ret')
 tok(c,0x001E,0x28,0x06005273,'MatchSEData.GetMatchSEParam')
 tok(c,0x0025,0x28,0x0A00002A,'Object.op_Implicit')
 br(c,0x002A,0x39,0x0144,'no player -> shared')
 tok(c,0x0030,0x7B,0x0400605C,'Player.isVibratePad');br(c,0x0035,0x39,0x009F,'vibration gate')
 tok(c,0x003B,0x7B,0x04008667,'MatchSEParam.vibTime')
 br(c,0x0043,0x3D,0x004B,'vibTime positive')
 if c[0x0048:0x004B]!=bytes([0x1F,0x0A,0x0C]):raise E('vib floor10')
 br(c,0x004E,0x3F,0x0056,'vibTime <60')
 if c[0x0053:0x0056]!=bytes([0x1F,0x3C,0x0C]):raise E('vib cap60')
 tok(c,0x0057,0x7B,0x04008665,'vib large');f32(c,0x005C,0.0,'vib large zero');br(c,0x0061,0x40,0x0076,'large nonzero')
 tok(c,0x0067,0x7B,0x04008666,'vib small');f32(c,0x006C,0.0,'vib small zero');br(c,0x0071,0x3B,0x009F,'both zero')
 tok(c,0x0077,0x7B,0x0400602E,'plCont_Pad gate');br(c,0x007C,0x39,0x009F,'pad absent')
 tok(c,0x0087,0x7B,0x040061C5,'pad port');tok(c,0x008D,0x7B,0x04008665,'vib large call');f32(c,0x0094,60.0,'vib divisor');tok(c,0x009A,0x28,0x06001FB3,'SetVibration')
 if c[0x00A0:0x00A2]!=bytes([0x1F,0x1F]):raise E('seid31')
 br(c,0x00A2,0x3B,0x00AF,'seid31')
 if c[0x00A8:0x00AA]!=bytes([0x1F,0x20]):raise E('seid32')
 br(c,0x00AA,0x40,0x00B5,'seid32')
 tok(c,0x00B0,0x6F,0x06004F7E,'PlayBreathEffect')
 if c[0x00B6]!=0x1B:raise E('seid5')
 br(c,0x00B7,0x40,0x00EA,'seid5 skip')
 tok(c,0x00BD,0x7B,0x04005FB4,'costumeData');tok(c,0x00C2,0x7B,0x04000D5D,'layerTex')
 if c[0x00C7:0x00C9]!=bytes([0x1E,0x17]):raise E('layerTex 8,1')
 tok(c,0x00C9,0x28,0x0A000669,'layerTex Get');tok(c,0x00CE,0x28,0x0A000015,'String.IsNullOrEmpty');br(c,0x00D3,0x39,0x00D9,'nonempty')
 if c[0x00D8]!=0x2A:raise E('empty return')
 tok(c,0x00DA,0x7B,0x04005FA7,'FormRen');tok(c,0x00DF,0x7B,0x04002744,'pos_OutOfRing');br(c,0x00E4,0x39,0x00EA,'not out')
 if c[0x00E9]!=0x2A:raise E('out return')
 for off,val in [(0x00F9,9),(0x0101,10),(0x0109,11),(0x0111,12),(0x0119,13),(0x0121,14),(0x0129,58)]:
  if c[off:off+2]!=bytes([0x1F,val]):raise E('raw set '+str(val))
 tok(c,0x0131,0x7B,0x04005FA7,'FormRen remap');tok(c,0x0136,0x7B,0x04002744,'pos_OutOfRing remap');br(c,0x013B,0x39,0x0144,'inside no remap')
 if c[0x0140:0x0144]!=bytes([0x1F,0x30,0x10,0x01]):raise E('seid=48')
 if c[0x0144:0x0147]!=bytes([0x03,0x1F,0x1E]):raise E('seid30')
 br(c,0x0147,0x40,0x0157,'seid30 branch')
 tok(c,0x014C,0x7E,0x04005899,'MatchUI.inst');tok(c,0x0152,0x6F,0x060049F3,'Show_Critical')
 tok(c,0x0158,0x7B,0x040086E5,'wait list #1');br(c,0x015F,0x39,0x0165,'wait zero')
 if c[0x0164]!=0x2A:raise E('wait return')
 tok(c,0x0166,0x7B,0x040086E5,'wait list #2')
 if c[0x016B:0x016E]!=bytes([0x03,0x18,0x9E]):raise E('wait set2')
 if c[0x016E:0x0170]!=bytes([0x03,0x04]):raise E('final args')
 tok(c,0x0170,0x28,0x060052A8,'Menu_SoundManager.Play_MatchSE')
 if c[0x0175]!=0x2A:raise E('ret')
 tok(cs['Wrapper'],0x0059,0x6F,0x06005277,'FACT-0058 caller')
 return {'dll_sha256':DLL_SHA,'method':{'code_size':len(c),'code_sha256':M['Core'][2]},'caller':'FACT-0058'}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--out');x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_MATCH_SE_PLAYER_PLAY_MATCH_SE: PASS');return 0
 except (OSError,ValueError,E) as e:
  print('PROVE_MATCH_SE_PLAYER_PLAY_MATCH_SE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
