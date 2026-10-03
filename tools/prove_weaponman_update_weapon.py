#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weapon_update_falling as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006AD0;RVA=0x00435634;ROW='345643000000860033cf0a005c480000bf4d';SIG='200001';LOCAL=0x11001611;LOCAL_SIG='07020812b508'
BODY=bytes.fromhex('160a3823000000027becb60004069a0b07282a00000a3a050000003806000000076fbd6a00060617580a061e3fd6ffffff2a');SHA='35d1ad134ac75a73b958fd378c3a108d4911f9faddf0d99b383f0062de3c2b6a'
FIELD=0x0400B6EC;FIELD_ROW='0600aa4f06009d190000';FIELD_SIG='061d12b508'
IMPLICIT=0x0A00002A;IMPLICIT_ROW='d100000085510600e9490000';IMPLICIT_SIG='0001021269'
CHILD=0x06006ABD;CHILD_RVA=0x00435000;CHILD_SIZE=351;CHILD_SHA='e8abda8319bdbcd424c4a521ed8decbb056271a54e759da39759a0eb46748263';CHILD_IL=0x21
CALLERS=[
 (0x06004935,'MatchMain','Update_EntranceScene',0x002AA570,822,'574be9a2193d91b436a4a241a5dee31bd03c08b32ca09d28dbdf4afd60990cde',0x0242),
 (0x06004936,'MatchMain','Update_Match',0x002AA8B4,1152,'b6841694e03be5ca4c73e966a13802de9fe7339ab63540ffdf5edaee96ea9dfe',0x03E8)
]
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def method_meta(pe,ss,rows,s,b,ix,z,o,sb,bb,mm,tok):
 rid=tok&0xffffff;rp=o[6]+(rid-1)*z[6];rva=struct.unpack_from('<I',pe,rp)[0];p=rp+8;ni,p=base.rd(pe,p,s);si,p=base.rd(pe,p,b);plist,p=base.rd(pe,p,ix(8))
 start,body=base.meth(pe,ss,rva)
 return {'rid':rid,'row':pe[rp:rp+z[6]].hex(),'rva':rva,'name':base.s_at(pe,sb,ni),'sig':base.blob(pe,bb,si).hex(),'plist':plist,'owner':mm.get(rid),'start':start,'body':body}
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,mm=base.owner_maps(pe,rows,s,ix,z,o,sb)
 m=method_meta(pe,ss,rows,s,b,ix,z,o,sb,bb,mm,T)
 if (m['row'],m['owner'],m['rva'],m['name'],m['sig'])!=(ROW,('WeaponMan',''),RVA,'UpdateWeapon',SIG):raise E('method metadata')
 nrp=o[6]+m['rid']*z[6]+8;_,nrp=base.rd(pe,nrp,s);_,nrp=base.rd(pe,nrp,b);nplist,_=base.rd(pe,nrp,ix(8))
 if m['plist']!=nplist:raise E('params')
 ho=base.off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0];ls=struct.unpack_from('<I',pe,ho+8)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],ls)!=(0x13,2,LOCAL):raise E('header')
 lr=LOCAL&0xffffff;lp=o[17]+(lr-1)*z[17];bi,_=base.rd(pe,lp,b)
 if base.blob(pe,bb,bi).hex()!=LOCAL_SIG:raise E('locals')
 c=m['body']
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 fr=FIELD&0xffffff;fp=o[4]+(fr-1)*z[4];q2=fp+2;fni,q2=base.rd(pe,q2,s);fsi,_=base.rd(pe,q2,b)
 if pe[fp:fp+z[4]].hex()!=FIELD_ROW or fm.get(fr)!=('WeaponMan','') or base.s_at(pe,sb,fni)!='WeaponObj' or base.blob(pe,bb,fsi).hex()!=FIELD_SIG:raise E('WeaponObj field')
 psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2
 rr=IMPLICIT&0xffffff;mp=o[10]+(rr-1)*z[10];q3=mp+psz;mni,q3=base.rd(pe,q3,s);msi,_=base.rd(pe,q3,b)
 if pe[mp:mp+z[10]].hex()!=IMPLICIT_ROW or base.s_at(pe,sb,mni)!='op_Implicit' or base.blob(pe,bb,msi).hex()!=IMPLICIT_SIG:raise E('op_Implicit member')
 if c[2]!=0x38 or (7+struct.unpack_from('<i',c,3)[0])!=0x2A:raise E('initial branch')
 if c[8]!=0x7b or struct.unpack_from('<I',c,9)[0]!=FIELD or c[14]!=0x9a:raise E('array load')
 if c[17]!=0x28 or struct.unpack_from('<I',c,18)[0]!=IMPLICIT:raise E('truth call')
 if c[22]!=0x3a or (27+struct.unpack_from('<i',c,23)[0])!=0x20:raise E('truth branch')
 if c[27]!=0x38 or (32+struct.unpack_from('<i',c,28)[0])!=0x26:raise E('false skip')
 if c[CHILD_IL]!=0x6f or struct.unpack_from('<I',c,CHILD_IL+1)[0]!=CHILD:raise E('child call')
 if c[43]!=0x1e or c[44]!=0x3f or (49+struct.unpack_from('<i',c,45)[0])!=0x07:raise E('loop bound')
 child=method_meta(pe,ss,rows,s,b,ix,z,o,sb,bb,mm,CHILD)
 if child['rva']!=CHILD_RVA or len(child['body'])!=CHILD_SIZE or hashlib.sha256(child['body']).hexdigest()!=CHILD_SHA:raise E('canonical child identity')
 expected=[]
 for tok,own,nm,rva,size,h,il in CALLERS:
  cm=method_meta(pe,ss,rows,s,b,ix,z,o,sb,bb,mm,tok)
  if cm['owner']!=(own,'') or cm['name']!=nm or cm['rva']!=rva or len(cm['body'])!=size or hashlib.sha256(cm['body']).hexdigest()!=h:raise E('caller identity '+nm)
  if cm['body'][il]!=0x6f or struct.unpack_from('<I',cm['body'],il+1)[0]!=T:raise E('caller edge '+nm)
  expected.append((cm['start']+il,0x6f))
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if sorted(actual)!=sorted(expected):raise E('global caller map '+repr(actual))
 internal=[]
 for i in range(len(c)-4):
  if c[i] in (0x28,0x6f):
   tok=struct.unpack_from('<I',c,i+1)[0]
   if tok>>24==0x06:internal.append((i,c[i],tok))
 if internal!=[(CHILD_IL,0x6f,CHILD)]:raise E('internal calls '+repr(internal))
 return {'code_size':50,'code_sha256':SHA,'loop_upper_bound_raw':8,'canonical_child_call_count':1,'direct_reference_count':2,'direct_caller_method_count':2}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'WeaponMan.UpdateWeapon':0,'Weapon.UpdateWeapon':0,'MatchMain.Update_EntranceScene':0,'MatchMain.Update_Match':0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip():raise E('CRC')
  names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=zf.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return dict(wanted,promoted_as_evidence=False)
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPONMAN_UPDATE_WEAPON: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPONMAN_UPDATE_WEAPON: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
