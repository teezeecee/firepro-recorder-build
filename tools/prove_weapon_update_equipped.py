#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weaponman_delete_all_weapons as base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006ABA;RVA=0x00434E20;ROW='204e43000000860005cf0a005c480000a84d';SIG='200001';LOCAL=0x1100028E;LOCAL_SIG='070112a788'
BODY=bytes.fromhex('285d500006027bdcb600046f655000060a06282a00000a3a1100000028c06a0006027bd2b600046fc66a00062a02067bee5f00047ddab6000402167ddbb6000402282800000a067ba75f00047b3127000428764800066fd700000a2a');SHA='3aa49b941ea49de68211c6b8bd98672b796ea36dc5eb99deeae75ef911aa737d'
OPS=[(0x0000,0x28,0x0600505D),(0x0006,0x7b,0x0400B6DC),(0x000B,0x6f,0x06005065),(0x0012,0x28,0x0A00002A),(0x001C,0x28,0x06006AC0),(0x0022,0x7b,0x0400B6D2),(0x0027,0x6f,0x06006AC6),(0x002F,0x7b,0x04005FEE),(0x0034,0x7d,0x0400B6DA),(0x003B,0x7d,0x0400B6DB),(0x0041,0x28,0x0A000028),(0x0047,0x7b,0x04005FA7),(0x004C,0x7b,0x04002731),(0x0051,0x28,0x06004876),(0x0056,0x6f,0x0A0000D7)]
FIELDS={0x0400B6DC:('Weapon','PlIdx','0608','0600bdb2030001000000'),0x0400B6D2:('Weapon','Idx','0608','06001d4f060001000000'),0x04005FEE:('Player','Zone','0611a85c','0600dde203009f300000'),0x0400B6DA:('Weapon','Zone','0611a85c','0600dde203009f300000'),0x0400B6DB:('Weapon','Dir','0611a768','0600314f0600ad370000'),0x04005FA7:('Player','FormRen','06129024','060029e00300260e0000'),0x04002731:('FormRenderer','playerLayerLocation','0611a368','0600cf1902008e190000')}
MEMBERS={0x0A00002A:('op_Implicit','0001021269','d100000085510600e9490000'),0x0A000028:('get_gameObject','2000120d','0901000076510600df490000'),0x0A0000D7:('set_layer','20010108','19000000e65706009f490000')}
CALLEES={0x0600505D:('PlayerMan','GetInst','000012a818'),0x06005065:('PlayerMan','GetPlObj','200112a78808'),0x06006AC0:('WeaponMan','GetInst','000012b510'),0x06006AC6:('WeaponMan','DeleteWeapon','20010108'),0x06004876:('LayerMan','GetLayerID','00010811a368')}
CALLER=(0x00435000,351,'e8abda8319bdbcd424c4a521ed8decbb056271a54e759da39759a0eb46748263',0x009A,0x28)
GETINST_RVA=0x00304880;GETINST_BODY=bytes.fromhex('7efa6100042a');GETINST_SHA='592555acaf96cbd806fb44a0dfd643c83f27267edcf79fe7ab57ec6c0457b1ff'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def method_meta(pe,rows,s,b,ix,z,o,sb,bb,mm,tok):
 rid=tok&0xffffff;rp=o[6]+(rid-1)*z[6];rva=struct.unpack_from('<I',pe,rp)[0];p=rp+8;ni,p=base.rd(pe,p,s);si,p=base.rd(pe,p,b);plist,p=base.rd(pe,p,ix(8));return rva,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex(),pe[rp:rp+z[6]].hex(),mm.get(rid),plist
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,mm=base.owner_maps(pe,rows,s,ix,z,o,sb)
 rva,name,sig,row,owner,plist=method_meta(pe,rows,s,b,ix,z,o,sb,bb,mm,T)
 if (rva,name,sig,row,owner)!=(RVA,'Update_Equipped',SIG,ROW,('Weapon','')):raise E('target metadata')
 nrp=o[6]+(T&0xffffff)*z[6]+8;_,nrp=base.rd(pe,nrp,s);_,nrp=base.rd(pe,nrp,b);nplist,_=base.rd(pe,nrp,ix(8))
 if plist!=nplist:raise E('unexpected params')
 ho=base.off(pe,ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,2,LOCAL):raise E('header')
 _,c=base.meth(pe,ss,RVA)
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 sp=o[17]+((LOCAL&0xffffff)-1)*z[17];bi,_=base.rd(pe,sp,b)
 if base.blob(pe,bb,bi).hex()!=LOCAL_SIG:raise E('local signature')
 for il,op,tok in OPS:
  if c[il]!=op or struct.unpack_from('<I',c,il+1)[0]!=tok:raise E('IL '+hex(il))
 if c[0x17]!=0x3a or 0x1c+struct.unpack_from('<i',c,0x18)[0]!=0x2d or c[0x2c]!=0x2a or c[0x5b]!=0x2a:raise E('branch/returns')
 for tok,(own,nm,sg,raw) in FIELDS.items():
  rid=tok&0xffffff;rp=o[4]+(rid-1)*z[4];p=rp+2;ni,p=base.rd(pe,p,s);si,_=base.rd(pe,p,b)
  if pe[rp:rp+z[4]].hex()!=raw or fm.get(rid)!=(own,'') or base.s_at(pe,sb,ni)!=nm or base.blob(pe,bb,si).hex()!=sg:raise E('field '+hex(tok))
 psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2
 for tok,(nm,sg,raw) in MEMBERS.items():
  rid=tok&0xffffff;rp=o[10]+(rid-1)*z[10];p=rp+psz;ni,p=base.rd(pe,p,s);si,_=base.rd(pe,p,b)
  if pe[rp:rp+z[10]].hex()!=raw or base.s_at(pe,sb,ni)!=nm or base.blob(pe,bb,si).hex()!=sg:raise E('member '+hex(tok))
 for tok,(own,nm,sg) in CALLEES.items():
  rv,n,msig,rw,ow,pl=method_meta(pe,rows,s,b,ix,z,o,sb,bb,mm,tok)
  if ow!=(own,'') or n!=nm or msig!=sg:raise E('callee '+hex(tok))
 crva,n,h,il,op=CALLER;start,cb=base.meth(pe,ss,crva)
 if len(cb)!=n or hashlib.sha256(cb).hexdigest()!=h or cb[il]!=op or struct.unpack_from('<I',cb,il+1)[0]!=T:raise E('caller')
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if actual!=[(start+il,op)]:raise E('target caller map '+repr(actual))
 _,gb=base.meth(pe,ss,GETINST_RVA)
 if gb!=GETINST_BODY or hashlib.sha256(gb).hexdigest()!=GETINST_SHA:raise E('PlayerMan.GetInst body')
 refs=[];needle=struct.pack('<I',0x0600505D)
 for mrid in range(1,rows[6]+1):
  mrp=o[6]+(mrid-1)*z[6];rv=struct.unpack_from('<I',pe,mrp)[0]
  if not rv:continue
  try:stt,mb=base.meth(pe,ss,rv)
  except Exception:continue
  for opc in (0x28,0x6f):
   pat=bytes([opc])+needle;pos=0
   while True:
    x=mb.find(pat,pos)
    if x<0:break
    refs.append((mrid,x,opc));pos=x+1
 if len(refs)!=171 or len({r[0] for r in refs})!=102:raise E('PlayerMan.GetInst caller cardinality')
 return {'code_size':92,'code_sha256':SHA,'direct_reference_count':1,'direct_caller_method_count':1,'open_player_man_get_inst_reference_count':171,'open_player_man_get_inst_caller_method_count':102}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Weapon.Update_Equipped':0,'Weapon.UpdateWeapon':0}
 with zipfile.ZipFile(path) as z:
  if z.testzip():raise E('CRC')
  names=[n for n in z.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=z.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return {'weapon_update_equipped_row_count':0,'weapon_update_weapon_row_count':0,'promoted_as_evidence':False}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPON_UPDATE_EQUIPPED: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPON_UPDATE_EQUIPPED: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
