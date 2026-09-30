#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={
'SetLastDamage':(0x002E197E,8,'aa8386105dc125796e2f61ab7fabade30391f80863d7231c8dce82017bc25826'),
'SetLastSkill':(0x002DE4CF,26,'743d99df562a3f16f12fd7da264fa22386474eec9f6eee8061d83c0c690fb959'),
'Bleeding':(0x002E828C,50,'2a308caf2b1dd0cb7166f4123e2a23ef24d8c3088294ddefea0f41384991c4a6'),
'SetDownTime':(0x002E18A0,64,'670ac32434c8e7ed6e8fea9b78f446e73ec1a0c0c58756add4cb55f6ed6a73c2')}
class ProofError(RuntimeError):pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from('<I',pe,0x3c)[0]
 if pe[q:q+4]!=b'PE\0\0':raise ProofError('not PE')
 n=struct.unpack_from('<H',pe,q+6)[0];osz=struct.unpack_from('<H',pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def rvaoff(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise ProofError('RVA unmapped')
def mcode(pe,ss,rva):
 o=rvaoff(ss,rva);b=pe[o]
 if b&3==2:h=1;n=b>>2
 elif b&3==3:
  fs=struct.unpack_from('<H',pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',pe,o+4)[0]
 else:raise ProofError('bad IL header')
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from('<I',c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from('<i',c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError('DLL SHA '+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=mcode(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+' body')
  cs[n]=c
 c=cs['SetLastDamage']
 if c[0:2]!=bytes([0x02,0x03]):raise ProofError('SetLastDamage args')
 tok(c,2,0x7D,0x04005FD1,'LastDamage store')
 if c[7]!=0x2A:raise ProofError('SetLastDamage ret')
 c=cs['SetLastSkill']
 if c[0:2]!=bytes([0x02,0x03]):raise ProofError('SetLastSkill args')
 tok(c,2,0x7D,0x04006036,'lastSkill store')
 if c[7:9]!=bytes([0x02,0x16]):raise ProofError('lastSkillHit zero')
 tok(c,9,0x7D,0x04006037,'lastSkillHit store')
 if c[14]!=0x02:raise ProofError('SetLastSkill this')
 tok(c,15,0x7B,0x0400602F,'plCont_AI')
 tok(c,20,0x6F,0x06005007,'ResetCheckedPriAct')
 if c[25]!=0x2A:raise ProofError('SetLastSkill ret')
 c=cs['Bleeding']
 if c[0:2]!=bytes([0x02,0x17]):raise ProofError('Bleeding flag args')
 tok(c,2,0x7D,0x0400605A,'isBleeding')
 if c[7]!=0x02:raise ProofError('Bleeding FormRen this')
 tok(c,8,0x7B,0x04005FA7,'FormRen')
 if c[13]!=0x17:raise ProofError('FormRen bleeding one')
 tok(c,14,0x7D,0x04002740,'FormRenderer isBleeding')
 tok(c,19,0x7E,0x040056FF,'MatchEvaluation inst')
 tok(c,24,0x7B,0x04005700,'PlResult')
 if c[29]!=0x02:raise ProofError('Bleeding PlIdx this')
 tok(c,30,0x7B,0x04005FA6,'PlIdx')
 if c[35:37]!=bytes([0x9A,0x25]):raise ProofError('PlResult elem dup')
 tok(c,37,0x7B,0x040056D7,'bledCnt read')
 if c[42:44]!=bytes([0x17,0x58]):raise ProofError('bledCnt plus1')
 tok(c,44,0x7D,0x040056D7,'bledCnt write')
 if c[49]!=0x2A:raise ProofError('Bleeding ret')
 c=cs['SetDownTime']
 if c[0:2]!=bytes([0x02,0x03]):raise ProofError('SetDownTime args')
 tok(c,2,0x7D,0x04005FCE,'DownTime store')
 if c[7]!=0x02:raise ProofError('DownTime read this')
 tok(c,8,0x7B,0x04005FCE,'DownTime read')
 if c[13]!=0x16:raise ProofError('DownTime compare zero')
 br(c,14,0x3C,0x001A,'DownTime bge')
 if c[19:21]!=bytes([0x02,0x16]):raise ProofError('DownTime clamp args')
 tok(c,21,0x7D,0x04005FCE,'DownTime clamp')
 tok(c,26,0x7E,0x04005899,'MatchUI check')
 tok(c,31,0x28,0x0A00002A,'MatchUI implicit')
 br(c,36,0x39,0x003F,'MatchUI absent')
 tok(c,41,0x7E,0x04005899,'MatchUI call inst')
 if c[46]!=0x02:raise ProofError('DownTime PlIdx this')
 tok(c,47,0x7B,0x04005FA6,'PlIdx')
 if c[52]!=0x02:raise ProofError('DownTime value this')
 tok(c,53,0x7B,0x04005FCE,'DownTime gauge value')
 tok(c,58,0x6F,0x060049F2,'SetGauge_DownTime')
 if c[63]!=0x2A:raise ProofError('SetDownTime ret')
 return {'dll_sha256':got,'methods':{n:{'code_size':len(cs[n]),'code_sha256':M[n][2]} for n in M}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--out');a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_PLAYER_SMALL_AFTERMATH_HELPERS: PASS');return 0
 except (OSError,ValueError,ProofError) as e:print('PROVE_PLAYER_SMALL_AFTERMATH_HELPERS: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
