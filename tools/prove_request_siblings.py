#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
METHODS={
 'ReqSerialAnm':(0x002D9F13,21,'ba11f4c9eb5c4039a8ba03055c42e707db927df9884b7e4a03d5ce45cc2b730e',2,0x04005EDA),
 'ReqSkillAnm':(0x002D9F29,21,'ac3eec081214a41850096a738ad0778366871ea77181e1fa20c4eb73915af81e',3,0x04005EDB),
}
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
 pe=Path(path).read_bytes();ss=sections(pe);out={}
 for name,(rva,size,sha,reqtype,idfield) in METHODS.items():
  code=mcode(pe,ss,rva)
  if len(code)!=size or hashlib.sha256(code).hexdigest()!=sha:raise ProofError(name+' body')
  if code[0]!=0x02 or code[1]!=(0x16+reqtype):raise ProofError(name+' AnmReqType literal')
  tok(code,0x0002,0x7D,0x04005ECF,name+' AnmReqType')
  if code[0x0007]!=0x02 or code[0x0008]!=0x03:raise ProofError(name+' arg1')
  tok(code,0x0009,0x7D,idfield,name+' id field')
  if code[0x000E]!=0x02:raise ProofError(name+' InitAnmWork receiver')
  tok(code,0x000F,0x28,0x06004E6C,name+' InitAnmWork')
  if code[0x0014]!=0x2A:raise ProofError(name+' ret')
  out[name]={'rva':f'0x{rva:08X}','code_size':len(code),'code_sha256':sha}
 return {'dll_sha256':got,'methods':out}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--out');a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_REQUEST_SIBLINGS: PASS');return 0
 except (OSError,ValueError,ProofError) as e:
  print('PROVE_REQUEST_SIBLINGS: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
