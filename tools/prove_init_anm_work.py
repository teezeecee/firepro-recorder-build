#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
RVA=0x002D9DD8
CODE_SIZE=303
CODE_SHA='cf51dba42ef7e38fee750ed4a8e5eb449511a11583f6bffbdbec3a9e2802250f'
class ProofError(RuntimeError): pass

def sha_path(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1024*1024),b''):h.update(c)
 return h.hexdigest()

def sections(pe):
 q=struct.unpack_from('<I',pe,0x3c)[0]
 if pe[q:q+4]!=b'PE\0\0':raise ProofError('not PE')
 n=struct.unpack_from('<H',pe,q+6)[0];osz=struct.unpack_from('<H',pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8);out.append((va,vs,rp,rs))
 return out

def rvaoff(pe,ss,rva):
 for va,vs,rp,rs in ss:
  if va<=rva<va+max(vs,rs):return rp+rva-va
 raise ProofError('RVA unmapped')

def mcode(pe,ss,rva):
 o=rvaoff(pe,ss,rva);b=pe[o]
 if b&3==2:h=1;n=b>>2
 elif b&3==3:
  fs=struct.unpack_from('<H',pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',pe,o+4)[0]
 else:raise ProofError('bad IL header')
 return pe[o+h:o+h+n]

def tok(code,off,op,t,label):
 if code[off]!=op or struct.unpack_from('<I',code,off+1)[0]!=t:raise ProofError(label)

def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError('DLL SHA '+got)
 pe=Path(path).read_bytes();code=mcode(pe,sections(pe),RVA)
 if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA:raise ProofError('InitAnmWork body')
 stores=[
  (0x0002,0x04005EEC),(0x0009,0x04005ED2),(0x0010,0x04005ED3),(0x0017,0x04005ED4),(0x001E,0x04005EDE),
  (0x002E,0x04005FBE),(0x003A,0x04006019),(0x0041,0x04005EE5),(0x0048,0x04005EE6),(0x004F,0x04005EE7),
  (0x0056,0x04005EE8),(0x005D,0x04005EE9),(0x0064,0x04005EEB),(0x006B,0x04005EEA),(0x0072,0x04005EED),
  (0x0079,0x04005EEE),(0x0085,0x04006058),(0x0091,0x04006059),(0x009D,0x04006064),(0x00A9,0x04006048),
  (0x00B5,0x04006049),(0x00C1,0x0400604B),(0x00CD,0x0400604C),(0x00D9,0x0400604F),(0x00E5,0x04006053),
  (0x00F1,0x04006055),(0x00FD,0x0400605B),(0x0109,0x0400605D),(0x0115,0x04006071),(0x0129,0x04005FBB)]
 for off,t in stores:tok(code,off,0x7D,t,f'store {off:#x}')
 tok(code,0x0121,0x7B,0x04005FBB,'Status3 load')
 if code[0x0126]!=0x1F or code[0x0127]!=0xF7 or code[0x0128]!=0x5F:raise ProofError('Status3 mask')
 if code[0x0029]!=0x20 or struct.unpack_from('<i',code,0x002A)[0]!=192:raise ProofError('FoxSleepCnt constant')
 if code[0x012E]!=0x2A:raise ProofError('ret')
 return {'dll_sha256':got,'code_size':len(code),'code_sha256':CODE_SHA,'verified_store_count':len(stores)}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--out');a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_INIT_ANM_WORK: PASS');return 0
 except (OSError,ValueError,ProofError) as e:
  print('PROVE_INIT_ANM_WORK: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
