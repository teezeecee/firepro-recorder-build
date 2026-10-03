#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weaponman_get_inst as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006ACD; RVA=0x004355A0; ROW='a05543000000860094cf0a00ed370300b94d'; SIG='2002121511b50408'
FIELD=0x0400B6ED; FIELD_ROW='0600b44f060052480000'; FIELD_SIG='061412150200020000'
GET=0x0A001170; GET_ROW='84190000d8590600da570100'; GET_SIG='200212150808'; GET_PARENT_RAW=6532
LOCAL_SIG_TOKEN=0x1100003A; LOCAL_SIG='070108'
BODY=bytes.fromhex('040a03450c00000005000000050000000c0000000c0000000c0000000c0000000c00000015000000150000001500000015000000050000003817000000040a3810000000041c5d0a3807000000160a3800000000027bedb600040306287011000a2a')
SHA='38d479af573bd1d4c4f72ad8947250d2ef5e4353f720d8c431daa0e3551dfb35'
CALLERS=[
(0x003BA0AC,803,'7e84c893b56541fcd52c58e1b6bb702745dacd99223cb9a9de52328d25a61663',0x01E0,0x6F),
(0x00420B80,2551,'1484ea60834605c7a2d269f1a7d1b2449cd9fc49e8549d8893824663d1a28413',0x0440,0x6F),
(0x004217AC,2212,'9b9c1b949c09da761e0b466cf93018f76da86747097e634cfa52073723a950fd',0x04AB,0x6F),
(0x00434C1A,44,'9fd8e4c6ea0c03f75b3de3aabfbe56ed4bf2f902ffe76bb13f7f57dee7b2c1b3',0x0021,0x6F)]
class E(RuntimeError): pass

def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''): h.update(c)
 return h.hexdigest()

def s_at(pe,base,i):
 return pe[base+i:pe.index(b'\0',base+i)].decode()

def metadata(pe):
 ss,q=base.secs(pe); st,hs,rows,p=base.mdstreams(pe,ss,q); s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
 return ss,st,rows,s,b,ix,z,o,st['#Strings'][0],st['#Blob'][0]

def owner_for(pe,rows,s,ix,z,o,strings,table,rid):
 key_off=lambda p:(p+4 if table==6 else p+4)
 # TypeDef row: Flags, Name, Namespace, Extends, FieldList, MethodList.
 ext_sz=4 if max(rows.get(t,0) for t in (2,1,27))>=16384 else 2
 for tr in range(1,rows[2]+1):
  p=o[2]+(tr-1)*z[2]+4
  ni,p=base.rd(pe,p,s); _,p=base.rd(pe,p,s); p+=ext_sz
  fl,p=base.rd(pe,p,ix(4)); ml,_=base.rd(pe,p,ix(6))
  if tr<rows[2]:
   np=o[2]+tr*z[2]+4
   _,np=base.rd(pe,np,s); _,np=base.rd(pe,np,s); np+=ext_sz
   nfl,np=base.rd(pe,np,ix(4)); nml,_=base.rd(pe,np,ix(6))
  else:
   nfl=rows[4]+1; nml=rows[6]+1
  start,end=(fl,nfl) if table==4 else (ml,nml)
  if start<=rid<end:return s_at(pe,strings,ni)
 raise E('owner')

def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,st,rows,s,b,ix,z,o,strings,blobs=metadata(pe)
 rid=T&0xffffff; rp=o[6]+(rid-1)*z[6]
 if pe[rp:rp+z[6]].hex()!=ROW:raise E('MethodDef row')
 rva=struct.unpack_from('<I',pe,rp)[0]; p=rp+8
 ni,p=base.rd(pe,p,s); si,p=base.rd(pe,p,b); plist,p=base.rd(pe,p,ix(8))
 if (rva,s_at(pe,strings,ni),base.blob(pe,blobs,si).hex(),owner_for(pe,rows,s,ix,z,o,strings,6,rid))!=(RVA,'GetWeaponSprite',SIG,'WeaponMan'):raise E('method metadata')
 nrp=o[6]+rid*z[6]+8; _,nrp=base.rd(pe,nrp,s); _,nrp=base.rd(pe,nrp,b); nplist,_=base.rd(pe,nrp,ix(8))
 pars=[]
 for pr in range(plist,nplist):
  pp=o[8]+(pr-1)*z[8]; seq=struct.unpack_from('<H',pe,pp+2)[0]; pn,_=base.rd(pe,pp+4,s); pars.append((seq,s_at(pe,strings,pn)))
 if pars!=[(1,'kind'),(2,'pat')]:raise E('parameters')
 co,c=base.meth(pe,ss,RVA)
 if len(c)!=98 or hashlib.sha256(c).hexdigest()!=SHA or c!=BODY:raise E('body')
 # fat header flags/max-stack/local sig are pinned by raw header.
 ho=base.off(ss,RVA); fs=struct.unpack_from('<H',pe,ho)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,3,LOCAL_SIG_TOKEN):raise E('header')
 if c[3]!=0x45 or struct.unpack_from('<I',c,4)[0]!=12:raise E('switch')
 rel=[struct.unpack_from('<i',c,8+4*i)[0] for i in range(12)]
 if [56+x for x in rel]!=[0x3d,0x3d,0x44,0x44,0x44,0x44,0x44,0x4d,0x4d,0x4d,0x4d,0x3d]:raise E('switch targets')
 if c[0x44:0x4d]!=bytes.fromhex('041c5d0a3807000000'):raise E('modulo arm')
 # field identity and owner
 fr=FIELD&0xffffff; fp=o[4]+(fr-1)*z[4]
 if pe[fp:fp+z[4]].hex()!=FIELD_ROW or owner_for(pe,rows,s,ix,z,o,strings,4,fr)!='WeaponMan':raise E('field row/owner')
 q=fp+2; fni,q=base.rd(pe,q,s); fsi,_=base.rd(pe,q,b)
 if s_at(pe,strings,fni)!='WeaponSprite' or base.blob(pe,blobs,fsi).hex()!=FIELD_SIG:raise E('field identity')
 # MemberRef identity
 rr=GET&0xffffff; mp=o[10]+(rr-1)*z[10]
 if pe[mp:mp+z[10]].hex()!=GET_ROW:raise E('member row')
 mrpsz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=8192 else 2
 cls,q=base.rd(pe,mp,mrpsz); gni,q=base.rd(pe,q,s); gsi,_=base.rd(pe,q,b)
 if cls!=GET_PARENT_RAW or s_at(pe,strings,gni)!='Get' or base.blob(pe,blobs,gsi).hex()!=GET_SIG:raise E('member identity')
 # local signature
 sp=o[17]+(0x3a-1)*z[17]; bi,_=base.rd(pe,sp,b)
 if base.blob(pe,blobs,bi).hex()!=LOCAL_SIG:raise E('local signature')
 # exact 4-callsite map, with no call or callvirt occurrences elsewhere in the PE.
 expected=[]
 for rva,n,h,il,op in CALLERS:
  cstart,mc=base.meth(pe,ss,rva)
  if len(mc)!=n or hashlib.sha256(mc).hexdigest()!=h or mc[il]!=op or struct.unpack_from('<I',mc,il+1)[0]!=T:raise E('caller')
  expected.append((cstart+il,op))
 actual=[]
 needle=struct.pack('<I',T)
 for op in (0x28,0x6F):
  pat=bytes([op])+needle; pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,op));pos=x+1
 if sorted(actual)!=sorted(expected):raise E('global caller map '+repr(actual))
 return {'code_size':98,'code_sha256':SHA,'direct_reference_count':4,'direct_caller_method_count':4}

def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'WeaponMan.GetWeaponSprite':0,'PartsAllBtn.SetBtnIdx':0,'FormRenderer_Craft.SetForm':0,'FormRenderer_Craft.SetAtkRangForm':0,'Weapon.SetPattern':0}
 with zipfile.ZipFile(path) as z:
  if z.testzip():raise E('R6 CRC')
  names=[n for n in z.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=z.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return {'weaponman_get_weapon_sprite_row_count':0,'direct_caller_rows':0,'promoted_as_evidence':False}

def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPONMAN_GET_WEAPON_SPRITE: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPONMAN_GET_WEAPON_SPRITE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
