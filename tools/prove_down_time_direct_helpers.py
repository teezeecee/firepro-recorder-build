#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={'SetStunTime':(0x002E193F,27,'f1cf347336997ae6ca3fc68973801bfad9697cf43326c86143a6cfa7cbb96074'),'GetParamRate':(0x002B0D74,16,'60de3a243171244b6e09508e9a73f00d82aa76207ad3e8dd046322bc7b849e6c')}
class E(RuntimeError):pass
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def secs(d):
 q=struct.unpack_from('<I',d,0x3c)[0];n=struct.unpack_from('<H',d,q+6)[0];os=struct.unpack_from('<H',d,q+20)[0];s=q+24+os;z=[]
 for i in range(n):
  o=s+40*i;vs,va,rs,rp=struct.unpack_from('<IIII',d,o+8);z.append((va,max(vs,rs),rp))
 return z
def code(d,ss,r):
 for va,sz,rp in ss:
  if va<=r<va+sz:o=rp+r-va;break
 b=d[o]
 if b&3==2:h=1;n=b>>2
 else:
  fs=struct.unpack_from('<H',d,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',d,o+4)[0]
 return d[o+h:o+h+n]
def tok(c,o,op,t):
 if c[o]!=op or struct.unpack_from('<I',c,o+1)[0]!=t:raise E(hex(o))
def verify(p):
 got=sha(p)
 if got!=DLL_SHA:raise E(got)
 d=Path(p).read_bytes();ss=secs(d);cs={}
 for n,(r,s,h) in M.items():
  c=code(d,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise E(n)
  cs[n]=c
 c=cs['SetStunTime'];tok(c,2,0x7D,0x04005FD0);tok(c,8,0x7B,0x04005FD0)
 if c[13]!=0x16 or c[14]!=0x3C or 14+5+struct.unpack_from('<i',c,15)[0]!=0x1A:raise E('stun branch')
 tok(c,21,0x7D,0x04005FD0)
 c=cs['GetParamRate']
 if c[0]!=0x02 or c[1]!=0x22 or struct.unpack_from('<f',c,2)[0]!=65535.0 or c[6]!=0x5B:raise E('rate div')
 if c[7]!=0x22 or struct.unpack_from('<f',c,8)[0]!=100.0 or c[12:16]!=bytes([0x5A,0x0A,0x06,0x2A]):raise E('rate tail')
 return {'dll_sha256':got,'methods':{n:{'code_size':len(cs[n]),'code_sha256':M[n][2]} for n in M}}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);x=a.parse_args()
 try:r=verify(x.dll);print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_DOWN_TIME_DIRECT_HELPERS: PASS');return 0
 except Exception as e:print('PROVE_DOWN_TIME_DIRECT_HELPERS: FAIL');print(e);return 1
if __name__=='__main__':raise SystemExit(main())
