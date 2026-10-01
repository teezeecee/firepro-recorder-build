#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={'Fade':(0x002B76FD,16,'8ab025c02e60a82d0238a60fbf523b6ad20647ca0ed32600a0fdf8b2df1a0083'),'PlayMatchSE':(0x002B0AE4,95,'20b2b0b4629e94a1522ac997f16d94062fd0e3ad779184615939a1ee3a794aae')}
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
 c=cs['Fade']
 if c[0]!=0x02:raise E('this')
 tok(c,1,0x7B,0x04005920,'NowFrm')
 if c[6]!=0x16:raise E('zero')
 br(c,7,0x3D,0x000E,'NowFrm > 0 false')
 if c[0x0C:0x10]!=bytes([0x17,0x2A,0x16,0x2A]):raise E('returns')
 tok(cs['PlayMatchSE'],0x24,0x6F,0x06004A7D,'FACT-0058 caller')
 return {'dll_sha256':DLL_SHA,'method':{'code_size':len(c),'code_sha256':M['Fade'][2]},'true_condition':'NowFrm <= 0'}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--out');x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_FADE_IS_FADE_FINISH: PASS');return 0
 except (OSError,ValueError,E) as e:
  print('PROVE_FADE_IS_FADE_FINISH: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
