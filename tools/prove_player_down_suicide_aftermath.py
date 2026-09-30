#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={'CalcDownTime':(0x002E6CD0,422,'f02235b113abcab029951822052639084b3692e7924ae6c3b9ac85e4c86a3a88'),'ApplySuicideDamage':(0x002E6E84,247,'ab7e73a9dbfa03ab3a998354ee2482425c0cce67a94c2376bb75edb06a5c7446')}
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
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from('<f',c,o+1)[0]!=struct.unpack('<f',struct.pack('<f',v))[0]:raise ProofError(l)
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from('<i',c,o+1)[0]!=v:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError('DLL SHA '+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=mcode(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+' body')
  cs[n]=c
 c=cs['CalcDownTime']
 checks=[(0x0000,0x7E,0x04006355,'Ring.inst'),(0x0005,0x7B,0x0400637A,'venueSetting'),(0x000C,0x7B,0x04006050,'standing'),(0x0018,0x28,0x06004EDA,'SetStunTime0'),(0x001E,0x7B,0x04005FCE,'DownTime'),(0x0029,0x7B,0x04006051,'disable'),(0x0034,0x7B,0x04005FD1,'LastDamage'),(0x0040,0x7B,0x04005FBF,'HP'),(0x0079,0x28,0x06004EDA,'SetStunTime'),(0x00A5,0x28,0x06004ED8,'SetDownTime'),(0x00AB,0x7B,0x04006468,'ringKind'),(0x00BC,0x28,0x06004975,'GetParamRateHP'),(0x00D1,0x28,0x06004975,'GetParamRateSP'),(0x00F1,0x28,0x06004EDA,'Stun960'),(0x0101,0x28,0x06004ED8,'Down1200'),(0x0108,0x7D,0x04006051,'disableStore'),(0x010E,0x7B,0x04005FBD,'spFlags'),(0x0153,0x28,0x06004ED8,'DownEighth'),(0x0166,0x7B,0x040057F9,'10Count'),(0x0182,0x28,0x06004ED8,'Down10Count'),(0x0189,0x7B,0x040057E6,'S1'),(0x0194,0x7B,0x04006074,'S1Recv'),(0x01A0,0x28,0x06004ED8,'DownS1')]
 for x in checks:tok(c,*x)
 for x in [(0x00C6,0x42,0x0106,'HP bgt.un'),(0x00DB,0x42,0x0106,'SP bgt.un'),(0x017B,0x44,0x0187,'10count blt.un')]:br(c,*x)
 for o,v,l in [(0x0039,65535.0,'base'),(0x0053,49151.0,'stunTh'),(0x005E,32767.0,'sub'),(0x0064,256.0,'div'),(0x007E,40959.0,'standingCap'),(0x008A,65535.0,'cap'),(0x009B,256.0,'downDiv'),(0x00C1,0.4000000059604645,'hpRate'),(0x00D6,0.4000000059604645,'spRate'),(0x0120,3072.0,'hpLo'),(0x0130,13056.0,'hpHi'),(0x0140,39168.0,'spWin'),(0x0176,32768.0,'tenHP')]:f32(c,o,v,l)
 i4(c,0x00EC,960,'960');i4(c,0x00FC,1200,'1200')
 if c[0x0113:0x0115]!=bytes([0x18,0x5F]):raise ProofError('mask2')
 if c[0x0151:0x0153]!=bytes([0x1E,0x5B]):raise ProofError('divide8')
 if c[0x01A5]!=0x2A:raise ProofError('CalcDownTime ret')
 c=cs['ApplySuicideDamage']
 checks=[(0x0000,0x7E,0x04005633,'hpTbl'),(0x000B,0x28,0x0600495C,'GetHealth'),(0x0014,0x7E,0x04005644,'failureTbl'),(0x001F,0x7B,0x0400108B,'fightStyle'),(0x0031,0x7B,0x04007C65,'sHP'),(0x0045,0x28,0x06004ECB,'AddHP'),(0x004C,0x28,0x06004EDC,'LastDamage'),(0x0057,0x7D,0x04005FD6,'KoLast'),(0x0072,0x7B,0x04007C66,'sSP'),(0x007B,0x28,0x06004ECF,'AddSP'),(0x008C,0x7B,0x04007C67,'sNeck'),(0x0095,0x28,0x06004ED4,'AddNeck'),(0x00A6,0x7B,0x04007C68,'sArm'),(0x00AF,0x28,0x06004ED5,'AddArm'),(0x00C0,0x7B,0x04007C69,'sWaist'),(0x00C9,0x28,0x06004ED6,'AddWaist'),(0x00DA,0x7B,0x04007C6A,'sLeg'),(0x00E3,0x28,0x06004ED7,'AddLeg'),(0x00EA,0x7D,0x0400606F,'starClear'),(0x00F1,0x7D,0x04006074,'s1Clear')]
 for x in checks:tok(c,*x)
 if c[0x0010:0x0013]!=bytes([0x18,0x5B,0x98]):raise ProofError('health /2 table')
 f32(c,0x003B,256.0,'hpScale');f32(c,0x0052,0.0,'koZero');f32(c,0x005F,256.0,'sharedScale')
 for o in [0x0077,0x0091,0x00AB,0x00C5,0x00DF]:
  if c[o:o+2]!=bytes([0x65,0x6B]):raise ProofError('neg/conv '+hex(o))
 if c[0x00F6]!=0x2A:raise ProofError('Suicide ret')
 return {'dll_sha256':got,'methods':{n:{'code_size':len(cs[n]),'code_sha256':M[n][2]} for n in M}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--out');a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_PLAYER_DOWN_SUICIDE_AFTERMATH: PASS');return 0
 except (OSError,ValueError,ProofError) as e:print('PROVE_PLAYER_DOWN_SUICIDE_AFTERMATH: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
