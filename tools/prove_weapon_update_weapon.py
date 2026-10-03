#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weapon_update_falling as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006ABD;RVA=0x00435000;ROW='005043000000860033cf0a005c480000a84d';SIG='200001';LOCAL=0x1100160D;LOCAL_SIG='07030c0c11b500'
BODY=bytes.fromhex('220000803f0a220000803f0b027bdbb60004193f080000000622000080bf5a0a027bd5b600040c084504000000050000005c00000067000000c4000000381c01000002282800000a6f5000000a027cd4b600047b0900000a027cd4b600047b5600000a027cd4b600047b0a00000a734400000a6f7a00000a02282800000a6f5000000a0607220000803f734400000a6f5d00000a38c50000000228ba6a000638ba0000000228bb6a000602282800000a6f5000000a027cd4b600047b0900000a027cd4b600047b5600000a027cd4b600047b0a00000a734400000a6f7a00000a02282800000a6f5000000a0607220000803f734400000a6f5d00000a385d0000000228bc6a000602282800000a6f5000000a027cd4b600047b0900000a027cd4b600047b5600000a027cd4b600047b0a00000a734400000a6f7a00000a02282800000a6f5000000a0607220000803f734400000a6f5d00000a38000000002a');SHA='e8abda8319bdbcd424c4a521ed8decbb056271a54e759da39759a0eb46748263'
CHILDREN=[(0x009A,0x06006ABA),(0x00A5,0x06006ABB),(0x0102,0x06006ABC)]
CALLER_T=0x06006AD0;CALLER_RVA=0x00435634;CALLER_SIZE=50;CALLER_SHA='35d1ad134ac75a73b958fd378c3a108d4911f9faddf0d99b383f0062de3c2b6a';CALLER_IL=0x21
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
 if (rva,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex())!=(RVA,'UpdateWeapon',SIG):raise E('metadata')
 nrp=o[6]+rid*z[6]+8;_,nrp=base.rd(pe,nrp,s);_,nrp=base.rd(pe,nrp,b);nplist,_=base.rd(pe,nrp,ix(8))
 if plist!=nplist:raise E('params')
 ho=base.off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0];ls=struct.unpack_from('<I',pe,ho+8)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],ls)!=(0x13,4,LOCAL):raise E('header')
 lr=LOCAL&0xffffff;lp=o[17]+(lr-1)*z[17];bi,_=base.rd(pe,lp,b)
 if base.blob(pe,bb,bi).hex()!=LOCAL_SIG:raise E('locals')
 start,c=base.meth(pe,ss,RVA)
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 if c[0x13]!=0x3f or (0x18+struct.unpack_from('<i',c,0x14)[0])!=0x20:raise E('Dir branch')
 if c[0x28]!=0x45 or struct.unpack_from('<I',c,0x29)[0]!=4:raise E('State switch')
 baseoff=0x3d
 targets=[baseoff+struct.unpack_from('<i',c,0x2d+4*i)[0] for i in range(4)]
 if targets!=[0x42,0x99,0xa4,0x101]:raise E('switch targets '+repr(targets))
 for il,tok in CHILDREN:
  if c[il]!=0x28 or struct.unpack_from('<I',c,il+1)[0]!=tok:raise E('child '+hex(il))
 internal=[]
 for i in range(len(c)-4):
  if c[i] in (0x28,0x6f):
   tok=struct.unpack_from('<I',c,i+1)[0]
   if tok>>24==0x06:internal.append((i,c[i],tok))
 if internal!=[(il,0x28,tok) for il,tok in CHILDREN]:raise E('internal calls '+repr(internal))
 cstart,cb=base.meth(pe,ss,CALLER_RVA)
 if len(cb)!=CALLER_SIZE or hashlib.sha256(cb).hexdigest()!=CALLER_SHA or cb[CALLER_IL]!=0x6f or struct.unpack_from('<I',cb,CALLER_IL+1)[0]!=T:raise E('caller')
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if actual!=[(cstart+CALLER_IL,0x6f)]:raise E('global caller map '+repr(actual))
 return {'code_size':351,'code_sha256':SHA,'child_call_count':3,'direct_reference_count':1,'direct_caller_method_count':1,'caller_code_size':50}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Weapon.UpdateWeapon':0,'WeaponMan.UpdateWeapon':0,'Weapon.Update_Equipped':0,'Weapon.Update_Falling':0,'Weapon.Update_ThrowIn':0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip():raise E('CRC')
  names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=zf.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return dict(wanted, promoted_as_evidence=False)
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPON_UPDATE_WEAPON: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPON_UPDATE_WEAPON: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
