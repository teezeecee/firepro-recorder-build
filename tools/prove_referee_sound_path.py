#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={
 'Outer':(0x002B0B50,87,'1875e52cbc086e1797f248a8f89340c75605d756409b3eb4e4bf1cea0d0080f9'),
 'Inner':(0x00321688,77,'43db6ad4797e97ed994bdc3c50bd925b35592f129148bd42103009de2d51b645'),
 'Update':(0x00321744,51,'8bb4fe7bdd1afe7b8440b399d90daf4e90da035214a8732bbb3f105723cdafcf'),
 'Leaf':(0x00322B90,122,'56ce94a2d961f8cb774c95924d1cab7a28ed7dc521501dc72ace69c7ce39c162')}
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
 c=cs['Outer']
 tok(c,0x0000,0x28,0x06004907,'MatchMain.GetInst')
 if c[0x0005]!=0x0A:raise E('stloc0')
 if c[0x0006:0x0008]!=bytes([0x06,0x14]):raise E('match null args')
 tok(c,0x0008,0x28,0x0A00000F,'Object.op_Inequality #1');br(c,0x000D,0x39,0x003B,'match-null dispatch')
 if c[0x0012]!=0x06:raise E('ldloc match')
 tok(c,0x0013,0x7B,0x04005752,'isFastForwardMatch');br(c,0x0018,0x39,0x003B,'fast false')
 tok(c,0x001D,0x7E,0x0400591E,'Fade.inst');tok(c,0x0022,0x6F,0x06004A7D,'Fade.IsFadeFinish');br(c,0x0027,0x39,0x003B,'fade false')
 if c[0x002C]!=0x06:raise E('ldloc match #2')
 tok(c,0x002D,0x7B,0x04005738,'MchFrameCnt')
 if c[0x0032:0x0035]!=bytes([0x1F,0x14,0x5E]):raise E('mod20')
 br(c,0x0035,0x39,0x003B,'remainder zero')
 if c[0x003A]!=0x2A:raise E('suppression return')
 tok(c,0x003B,0x7E,0x040086E4,'MatchSEPlayer.inst #1')
 if c[0x0040]!=0x14:raise E('ldnull')
 tok(c,0x0041,0x28,0x0A00000F,'Object.op_Inequality #2');br(c,0x0046,0x39,0x0056,'player absent return')
 tok(c,0x004B,0x7E,0x040086E4,'MatchSEPlayer.inst #2')
 if c[0x0050]!=0x02:raise E('seid forwarding')
 tok(c,0x0051,0x6F,0x06005278,'inner PlayRefereeSE')
 if c[0x0056]!=0x2A:raise E('outer return')
 c=cs['Inner']
 if c[0x0000:0x0003]!=bytes([0x03,0x1F,0x6D]):raise E('upper gate args')
 br(c,0x0003,0x3F,0x0009,'seid<109')
 if c[0x0008]!=0x2A:raise E('upper return')
 tok(c,0x0009,0x28,0x060050B2,'RefereeMan.GetInst');tok(c,0x000E,0x6F,0x060050B6,'GetRefereeObj')
 if c[0x0013]!=0x0A:raise E('stloc referee')
 if c[0x0014]!=0x06:raise E('ldloc referee')
 tok(c,0x0015,0x28,0x0A00002A,'Object.op_Implicit');br(c,0x001A,0x3A,0x0020,'referee present')
 if c[0x001F]!=0x2A:raise E('referee absent return')
 if c[0x0020:0x0022]!=bytes([0x03,0x16]):raise E('lower gate args')
 br(c,0x0022,0x3C,0x0028,'seid>=0')
 if c[0x0027]!=0x2A:raise E('negative return')
 f32(c,0x0028,1.0,'local volume 1'); 
 if c[0x002D]!=0x0B:raise E('stloc1')
 if c[0x002E]!=0x02:raise E('this wait')
 tok(c,0x002F,0x7B,0x040086E5,'wait list read')
 if c[0x0034:0x0036]!=bytes([0x03,0x94]):raise E('wait index')
 br(c,0x0036,0x39,0x003C,'wait zero')
 if c[0x003B]!=0x2A:raise E('wait nonzero return')
 if c[0x003C]!=0x02:raise E('this wait write')
 tok(c,0x003D,0x7B,0x040086E5,'wait list write')
 if c[0x0042:0x0045]!=bytes([0x03,0x18,0x9E]):raise E('raw2 store')
 if c[0x0045:0x0047]!=bytes([0x03,0x07]):raise E('final args')
 tok(c,0x0047,0x28,0x060052A8,'Menu_SoundManager.Play_MatchSE')
 if c[0x004C]!=0x2A:raise E('inner return')
 tok(cs['Update'],0x0008,0x7B,0x040086E5,'FACT-0063 shared field')
 return {'dll_sha256':DLL_SHA,'methods':{'outer':M['Outer'][2],'inner':M['Inner'][2]},'shared_wait_field':'0x040086E5'}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--out');x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_REFEREE_SOUND_PATH: PASS');return 0
 except (OSError,ValueError,E) as e:
  print('PROVE_REFEREE_SOUND_PATH: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
