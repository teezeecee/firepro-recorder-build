#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={'Update':(0x00321744,51,'8bb4fe7bdd1afe7b8440b399d90daf4e90da035214a8732bbb3f105723cdafcf'),'Play':(0x00321504,374,'4c90d23ad41281c6f3411dd71c82635d6b56e0a15c80f80d2abf775639f9a4f9')}
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E('dll')
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+' body')
  cs[n]=c
 c=cs['Update']
 if c[0:2]!=bytes([0x16,0x0A]):raise E('index init')
 br(c,0x0002,0x38,0x002A,'initial jump')
 if c[0x0007]!=0x02:raise E('this #1')
 tok(c,0x0008,0x7B,0x040086E5,'wait list read')
 if c[0x000D:0x0010]!=bytes([0x06,0x94,0x16]):raise E('element >0 operands')
 br(c,0x0010,0x3E,0x0026,'nonpositive skip')
 if c[0x0015]!=0x02:raise E('this #2')
 tok(c,0x0016,0x7B,0x040086E5,'wait list address')
 if c[0x001B]!=0x06:raise E('index address')
 if c[0x001C]!=0x8F or struct.unpack_from('<I',c,0x001D)[0]!=0x010000D7:raise E('ldelema int32')
 if c[0x0021:0x0026]!=bytes([0x25,0x4A,0x17,0x59,0x54]):raise E('dup/load/sub/store')
 if c[0x0026:0x002A]!=bytes([0x06,0x17,0x58,0x0A]):raise E('index increment')
 if c[0x002A:0x002D]!=bytes([0x06,0x1F,0x6D]):raise E('loop bound')
 br(c,0x002D,0x3F,0x0007,'signed blt loop')
 if c[0x0032]!=0x2A:raise E('return')
 p=cs['Play']
 tok(p,0x0158,0x7B,0x040086E5,'FACT-0060 wait read')
 tok(p,0x0166,0x7B,0x040086E5,'FACT-0060 wait write')
 if p[0x016B:0x016E]!=bytes([0x03,0x18,0x9E]):raise E('FACT-0060 raw2 store')
 return {'dll_sha256':DLL_SHA,'method':{'code_size':len(c),'code_sha256':M['Update'][2]},'raw_index_range':[0,108],'writer_fact':'FACT-0060'}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--out');x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_MATCH_SE_PLAYER_UPDATE_WAIT_LIST: PASS');return 0
 except (OSError,ValueError,E) as e:
  print('PROVE_MATCH_SE_PLAYER_UPDATE_WAIT_LIST: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
