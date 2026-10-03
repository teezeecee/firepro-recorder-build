#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weapon_update_falling as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006ABC;RVA=0x00434F38;ROW='384f43000000860024cf0a005c480000a84d';SIG='200001';LOCAL=0x1100001F;LOCAL_SIG='07010c'
BODY=bytes.fromhex('02257bd7b60004027bd8b60004283c00000a7dd7b60004027cd7b60004257b0900000a027bd9b600045a7d0900000a027cd7b60004257b0a00000a027bd9b600045a7d0a00000a02257bd4b60004027bd7b60004283c00000a7dd4b60004027cd7b600047b0900000a027cd7b600047b0900000a5a027cd7b600047b0a00000a027cd7b600047b0a00000a5a5828b609000a0a06226f12033b421d00000002167dd5b6000402283d00000a7dd7b6000402283d00000a7dd8b600042a')
SHA='0c414a06ab008a72015d27a098c79d068c39a442248446c4245d541423a35bf1'
FIELDS={
 0x0400B6D7:('Weapon','Vel','061119','0100214f060070000000'),
 0x0400B6D8:('Weapon','Acc','061119','0100254f060070000000'),
 0x0400B6D9:('Weapon','Damping','060c','0600294f060014000000'),
 0x0400B6D4:('Weapon','Pos','061119','0600d409040070000000'),
 0x0400B6D5:('Weapon','State','0611b500','06006e0000003d480000')
}
MEMBERS={
 0x0A00003C:(49,'op_Addition','0002111911191119','31000000635206002c4b0000'),
 0x0A000009:(49,'x','060c','31000000dfb6000014000000'),
 0x0A00000A:(49,'y','060c','31000000e1b6000014000000'),
 0x0A0009B6:(1537,'Sqrt','00010c0c','01060000fbe00600e34b0000'),
 0x0A00003D:(49,'get_zero','00001119','310000006f520600354b0000')
}
OPS=[
 (0x0002,0x7b,0x0400B6D7),(0x0008,0x7b,0x0400B6D8),(0x000d,0x28,0x0A00003C),(0x0012,0x7d,0x0400B6D7),
 (0x0018,0x7c,0x0400B6D7),(0x001e,0x7b,0x0A000009),(0x0024,0x7b,0x0400B6D9),(0x002a,0x7d,0x0A000009),
 (0x0030,0x7c,0x0400B6D7),(0x0036,0x7b,0x0A00000A),(0x003c,0x7b,0x0400B6D9),(0x0042,0x7d,0x0A00000A),
 (0x0049,0x7b,0x0400B6D4),(0x004f,0x7b,0x0400B6D7),(0x0054,0x28,0x0A00003C),(0x0059,0x7d,0x0400B6D4),
 (0x005f,0x7c,0x0400B6D7),(0x0064,0x7b,0x0A000009),(0x006a,0x7c,0x0400B6D7),(0x006f,0x7b,0x0A000009),
 (0x0076,0x7c,0x0400B6D7),(0x007b,0x7b,0x0A00000A),(0x0081,0x7c,0x0400B6D7),(0x0086,0x7b,0x0A00000A),
 (0x008d,0x28,0x0A0009B6),(0x00a0,0x7d,0x0400B6D5),(0x00a6,0x28,0x0A00003D),(0x00ab,0x7d,0x0400B6D7),
 (0x00b1,0x28,0x0A00003D),(0x00b6,0x7d,0x0400B6D8)
]
PARENT_RVA=0x00435000;PARENT_SIZE=351;PARENT_SHA='e8abda8319bdbcd424c4a521ed8decbb056271a54e759da39759a0eb46748263'
PARENT_CALLS=[(0x009A,0x06006ABA),(0x00A5,0x06006ABB),(0x0102,0x06006ABC)]

class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()

def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,mm=base.owner_maps(pe,rows,s,ix,z,o,sb)
 rid=T&0xffffff;rp=o[6]+(rid-1)*z[6]
 if pe[rp:rp+z[6]].hex()!=ROW or mm.get(rid)!=('Weapon',''):raise E('MethodDef row/owner')
 rva=struct.unpack_from('<I',pe,rp)[0];p=rp+8;ni,p=base.rd(pe,p,s);si,p=base.rd(pe,p,b);plist,p=base.rd(pe,p,ix(8))
 if (rva,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex())!=(RVA,'Update_ThrowIn',SIG):raise E('method metadata')
 nrp=o[6]+rid*z[6]+8;_,nrp=base.rd(pe,nrp,s);_,nrp=base.rd(pe,nrp,b);nplist,_=base.rd(pe,nrp,ix(8))
 if plist!=nplist:raise E('unexpected params')
 ho=base.off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,3,LOCAL):raise E('header')
 start,c=base.meth(pe,ss,RVA)
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 lr=LOCAL&0xffffff;sp=o[17]+(lr-1)*z[17];bi,_=base.rd(pe,sp,b)
 if base.blob(pe,bb,bi).hex()!=LOCAL_SIG:raise E('local signature')
 for il,op,tok in OPS:
  if c[il]!=op or struct.unpack_from('<I',c,il+1)[0]!=tok:raise E('IL '+hex(il))
 if c[0x94]!=0x22 or struct.unpack_from('<f',c,0x95)[0]!=struct.unpack('<f',bytes.fromhex('6f12033b'))[0]:raise E('speed threshold')
 if c[0x99]!=0x42 or (0x9e+struct.unpack_from('<i',c,0x9a)[0])!=0xbb:raise E('settle branch')
 for tok,(own,nm,sg,raw) in FIELDS.items():
  fr=tok&0xffffff;fp=o[4]+(fr-1)*z[4];q2=fp+2;fni,q2=base.rd(pe,q2,s);fsi,_=base.rd(pe,q2,b)
  if pe[fp:fp+z[4]].hex()!=raw or fm.get(fr)!=(own,'') or base.s_at(pe,sb,fni)!=nm or base.blob(pe,bb,fsi).hex()!=sg:raise E('field '+hex(tok))
 psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2
 for tok,(parent_raw,nm,sg,raw) in MEMBERS.items():
  rr=tok&0xffffff;mp=o[10]+(rr-1)*z[10];par,q3=base.rd(pe,mp,psz);mni,q3=base.rd(pe,q3,s);msi,_=base.rd(pe,q3,b)
  if pe[mp:mp+z[10]].hex()!=raw or par!=parent_raw or base.s_at(pe,sb,mni)!=nm or base.blob(pe,bb,msi).hex()!=sg:raise E('member '+hex(tok))
 for i in range(len(c)-4):
  if c[i] in (0x28,0x6f) and (struct.unpack_from('<I',c,i+1)[0]>>24)==0x06:raise E('unexpected internal game call')
 pstart,pb=base.meth(pe,ss,PARENT_RVA)
 if len(pb)!=PARENT_SIZE or hashlib.sha256(pb).hexdigest()!=PARENT_SHA:raise E('parent identity')
 raw_game=[]
 for i in range(len(pb)-4):
  if pb[i] in (0x28,0x6f):
   tok=struct.unpack_from('<I',pb,i+1)[0]
   if tok>>24==0x06:raw_game.append((i,pb[i],tok))
 if raw_game!=[(il,0x28,tok) for il,tok in PARENT_CALLS]:raise E('parent MethodDef call patterns '+repr(raw_game))
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if actual!=[(pstart+0x0102,0x28)]:raise E('global caller map '+repr(actual))
 return {'code_size':188,'code_sha256':SHA,'direct_reference_count':1,'direct_caller_method_count':1,'parent_methoddef_call_pattern_count':3}

def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Weapon.Update_ThrowIn':0,'Weapon.UpdateWeapon':0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip():raise E('CRC')
  names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=zf.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return {'weapon_update_throw_in_row_count':0,'weapon_update_weapon_row_count':0,'promoted_as_evidence':False}

def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPON_UPDATE_THROW_IN: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPON_UPDATE_THROW_IN: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
