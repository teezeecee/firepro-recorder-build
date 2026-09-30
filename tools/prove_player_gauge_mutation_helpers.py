#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
METHODS={
'AddHP':(0x002E12D4,118,'7bea96e74624b8014aab919f755fba46681651c5aa2227665f3809dd0eecd5b9','add',0x04005FBF,0x060049EF),
'SetHP':(0x002E1358,111,'9464ea04471ecb7c12d842bd75de42674848d322649a884fccbbf1d266e36b9a','set',0x04005FBF,0x060049EF),
'AddBP':(0x002E13D4,118,'f7f25fb62c16540e17a6f0dfb0eb138bbdc845c7af43eac9d5035c4686ecb1e6','add',0x04005FC1,0x060049F1),
'SetBP':(0x002E1458,111,'a2b699b33928252a7760f62e86cbdc9a72aaa080f2cd3ea9d62ba2f827cec706','set',0x04005FC1,0x060049F1),
'AddSP':(0x002E14D4,118,'2316bc2161b5cad37f892c724cff047f7599c5cefb0c4929e40f52f5589b7b36','add',0x04005FC0,0x060049F0),
'SetSP':(0x002E1558,111,'aa4a13340001d7b25181e1c10a729c1436490b51a6b8c821f5098db7b4eed89b','set',0x04005FC0,0x060049F0),
'AddHP_Neck':(0x002E1720,81,'06811329438dd3f627c163e6311e52ce59fae1f2e6ea89f4a6a8a74d9f007ca0','limb',0x04005FC2,None),
'AddHP_Arm':(0x002E1780,81,'10d9eb1af8841d2f9302a35ce081ca00d03f96bb4ddba9050bd4be5138d7b1ef','limb',0x04005FC3,None),
'AddHP_Waist':(0x002E17E0,81,'6252e60a604afd0da73eff0df982cf7cb310863d0c5e2f1f6d279b69de9bd96f','limb',0x04005FC4,None),
'AddHP_Leg':(0x002E1840,81,'ea3412cf696898ca16a9f88e35f8c1aac099ba393a324b7d23afb9c0ce1a00a8','limb',0x04005FC5,None)}
IMMORTAL=0x0400605E;UI=0x04005899;IMPLICIT=0x0A00002A;PLIDX=0x04005FA6
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
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from('<I',c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from('<i',c,o+1)[0]!=t:raise ProofError(l)
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from('<f',c,o+1)[0]!=struct.unpack('<f',struct.pack('<f',v))[0]:raise ProofError(l)
def common(c,n):
 if c[0]!=0x02:raise ProofError(n+' ldarg0')
 tok(c,1,0x7B,IMMORTAL,n+' isImmortal');br(c,6,0x39,12,n+' immortal gate')
 if c[11]!=0x2A:raise ProofError(n+' immortal ret')
def clamp(c,n,field,base):
 tok(c,base+1,0x7B,field,n+' low read');f32(c,base+6,0.0,n+' low zero');br(c,base+11,0x41,base+27,n+' bge.un')
 f32(c,base+17,0.0,n+' low store zero');tok(c,base+22,0x7D,field,n+' low store')
 tok(c,base+28,0x7B,field,n+' high read');f32(c,base+33,65535.0,n+' max');br(c,base+38,0x43,base+54,n+' ble.un')
 f32(c,base+44,65535.0,n+' high store max');tok(c,base+49,0x7D,field,n+' high store')
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError('DLL SHA '+got)
 pe=Path(path).read_bytes();ss=sections(pe);out={}
 for n,(rva,size,sha,kind,field,gauge) in METHODS.items():
  c=mcode(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+' body')
  common(c,n)
  if kind in ('add','limb'):
   if c[12:14]!=bytes([0x02,0x25]):raise ProofError(n+' add prefix')
   tok(c,14,0x7B,field,n+' add read')
   if c[19:21]!=bytes([0x03,0x58]):raise ProofError(n+' add operand')
   tok(c,21,0x7D,field,n+' add store');clamp(c,n,field,26);tail=80
  else:
   if c[12:14]!=bytes([0x02,0x03]):raise ProofError(n+' set args')
   tok(c,14,0x7D,field,n+' set store');clamp(c,n,field,19);tail=73
  if kind=='limb':
   if tail!=80 or c[80]!=0x2A:raise ProofError(n+' limb ret')
  else:
   tok(c,tail,0x7E,UI,n+' UI check');tok(c,tail+5,0x28,IMPLICIT,n+' UI implicit');br(c,tail+10,0x39,tail+37,n+' UI absent')
   tok(c,tail+15,0x7E,UI,n+' UI call')
   if c[tail+20]!=0x02:raise ProofError(n+' gauge this')
   tok(c,tail+21,0x7B,PLIDX,n+' PlIdx')
   if c[tail+26]!=0x02:raise ProofError(n+' gauge this2')
   tok(c,tail+27,0x7B,field,n+' gauge value');tok(c,tail+32,0x6F,gauge,n+' gauge call')
   if c[tail+37]!=0x2A:raise ProofError(n+' ret')
  out[n]={'code_size':len(c),'code_sha256':sha}
 return {'dll_sha256':got,'methods':out}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--out');a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_PLAYER_GAUGE_MUTATION_HELPERS: PASS');return 0
 except (OSError,ValueError,ProofError) as e:print('PROVE_PLAYER_GAUGE_MUTATION_HELPERS: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
