#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006ABB; RVA=0x00434E88; ROW='884e43000000860015cf0a005c480000a84d'; SIG='200001'
BODY=bytes.fromhex('02257bd7b60004027bd8b60004283c00000a7dd7b6000402257bd4b60004027bd7b60004283c00000a7dd4b60004027cd4b600047b5600000a027bddb60004425f000000027cd4b60004027bddb600047d5600000a027cd7b60004257b5600000a229a9999be5a7d5600000a027cd7b600047b5600000a284500000a226f12033b421d00000002167dd5b6000402283d00000a7dd7b6000402283d00000a7dd8b600042a')
SHA='a6c62583dc93b0e5f367e45b8ea8bb2499f87333aa6f39cd3c666d188b973e44'
FIELDS={
 0x0400B6D7:('Weapon','Vel','061119','0100214f060070000000'),
 0x0400B6D8:('Weapon','Acc','061119','0100254f060070000000'),
 0x0400B6D4:('Weapon','Pos','061119','0600d409040070000000'),
 0x0400B6DD:('Weapon','GroundY','060c','0600354f060014000000'),
 0x0400B6D5:('Weapon','State','0611b500','06006e0000003d480000')
}
MEMBERS={
 0x0A00003C:('op_Addition','0002111911191119','31000000635206002c4b0000'),
 0x0A000056:('z','060c','310000007553060014000000'),
 0x0A000045:('Abs','00010c0c','01060000ca520600e34b0000'),
 0x0A00003D:('get_zero','00001119','310000006f520600354b0000')
}
OPS=[
 (0x0002,0x7b,0x0400B6D7),(0x0008,0x7b,0x0400B6D8),(0x000d,0x28,0x0A00003C),(0x0012,0x7d,0x0400B6D7),
 (0x0019,0x7b,0x0400B6D4),(0x001f,0x7b,0x0400B6D7),(0x0024,0x28,0x0A00003C),(0x0029,0x7d,0x0400B6D4),
 (0x002f,0x7c,0x0400B6D4),(0x0034,0x7b,0x0A000056),(0x003a,0x7b,0x0400B6DD),
 (0x0045,0x7c,0x0400B6D4),(0x004b,0x7b,0x0400B6DD),(0x0050,0x7d,0x0A000056),
 (0x0056,0x7c,0x0400B6D7),(0x005c,0x7b,0x0A000056),(0x0067,0x7d,0x0A000056),
 (0x006d,0x7c,0x0400B6D7),(0x0072,0x7b,0x0A000056),(0x0077,0x28,0x0A000045),
 (0x0088,0x7d,0x0400B6D5),(0x008e,0x28,0x0A00003D),(0x0093,0x7d,0x0400B6D7),
 (0x0099,0x28,0x0A00003D),(0x009e,0x7d,0x0400B6D8)
]
CALLER=(0x00435000,351,'e8abda8319bdbcd424c4a521ed8decbb056271a54e759da39759a0eb46748263',0x00A5,0x28)
THROW_TOKEN=0x06006ABC; THROW_RVA=0x00434F38; THROW_SIZE=188; THROW_SHA='0c414a06ab008a72015d27a098c79d068c39a442248446c4245d541423a35bf1'; THROW_CALL_IL=0x0102

class E(RuntimeError): pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''): h.update(c)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from('<I',pe,0x3c)[0];n=struct.unpack_from('<H',pe,q+6)[0];z=struct.unpack_from('<H',pe,q+20)[0];s=q+24+z
 return [(lambda o:(struct.unpack_from('<I',pe,o+12)[0],max(struct.unpack_from('<I',pe,o+8)[0],struct.unpack_from('<I',pe,o+16)[0]),struct.unpack_from('<I',pe,o+20)[0]))(s+i*40) for i in range(n)],q
def off(ss,r):
 for a,n,p in ss:
  if a<=r<a+n:return p+r-a
 raise E('RVA '+hex(r))
def meth(pe,ss,r):
 o=off(ss,r);b=pe[o]
 if b&3==2:return o+1,pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from('<H',pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',pe,o+4)[0]
 return o+h,pe[o+h:o+h+n]
def mdstreams(pe,ss,q):
 oo=q+24;dd=oo+(112 if struct.unpack_from('<H',pe,oo)[0]==0x20b else 96)
 cli=off(ss,struct.unpack_from('<I',pe,dd+112)[0]);md=off(ss,struct.unpack_from('<I',pe,cli+8)[0])
 vl=struct.unpack_from('<I',pe,md+12)[0];p=(md+16+vl+3)&~3;_,ns=struct.unpack_from('<HH',pe,p);p+=4;st={}
 for _ in range(ns):
  a,n=struct.unpack_from('<II',pe,p);p+=8;e=pe.index(b'\0',p);name=pe[p:e].decode();p=(e+4)&~3;st[name]=(md+a,n)
 t=st['#~'][0];p=t+4;_,_,hs,_=struct.unpack_from('<BBBB',pe,p);p+=4;valid,_=struct.unpack_from('<QQ',pe,p);p+=16;rows={}
 for i in range(64):
  if valid>>i&1:rows[i]=struct.unpack_from('<I',pe,p)[0];p+=4
 return st,hs,rows,p
def rd(pe,p,n):return (struct.unpack_from('<I',pe,p)[0],p+4) if n==4 else (struct.unpack_from('<H',pe,p)[0],p+2)
def blob(pe,b,i):
 p=b+i;x=pe[p]
 if x<128:n=x;p+=1
 elif x<192:n=((x&63)<<8)|pe[p+1];p+=2
 else:n=((x&31)<<24)|(pe[p+1]<<16)|(pe[p+2]<<8)|pe[p+3];p+=4
 return pe[p:p+n]
def tables(pe,st,hs,rows,p):
 s=4 if hs&1 else 2;b=4 if hs&4 else 2
 def ix(t):return 4 if rows.get(t,0)>=65536 else 2
 def cx(ts,k):return 4 if max(rows.get(t,0) for t in ts)>=(1<<(16-k)) else 2
 z={0:2+s+3*(4 if hs&2 else 2),1:cx([0,26,35,1],2)+2*s,2:4+2*s+cx([2,1,27],2)+ix(4)+ix(6),3:ix(4),4:2+s+b,5:ix(6),6:8+s+b+ix(8),7:ix(8),8:4+s,9:ix(2)+cx([2,1,27],2),10:cx([2,1,26,6,27],3)+s+b,11:2+cx([4,8,23],2)+b,12:cx([6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43],5)+cx([6,10],3)+b,13:cx([4,8],1)+b,14:2+cx([2,6,32],2)+b,15:6+ix(2),16:4+ix(4),17:b}
 o={};c=p
 for i in range(18):
  if i in rows:o[i]=c;c+=z[i]*rows[i]
 return s,b,ix,z,o
def s_at(pe,sb,i):
 p=sb+i;return pe[p:pe.index(b'\0',p)].decode()
def owner_maps(pe,rows,s,ix,z,o,sb):
 ext=4 if max(rows.get(t,0) for t in (2,1,27))>=16384 else 2;types=[]
 for rid in range(1,rows[2]+1):
  p=o[2]+(rid-1)*z[2]+4;ni,p=rd(pe,p,s);nsi,p=rd(pe,p,s);p+=ext;fl,p=rd(pe,p,ix(4));ml,_=rd(pe,p,ix(6))
  types.append((s_at(pe,sb,ni),s_at(pe,sb,nsi),fl,ml))
 fm={};mm={}
 for i,(name,ns,fl,ml) in enumerate(types):
  nfl=types[i+1][2] if i+1<len(types) else rows[4]+1;nml=types[i+1][3] if i+1<len(types) else rows[6]+1
  for r in range(fl,nfl):fm[r]=(name,ns)
  for r in range(ml,nml):mm[r]=(name,ns)
 return fm,mm
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=secs(pe);st,hs,rows,tp=mdstreams(pe,ss,q);s,b,ix,z,o=tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,mm=owner_maps(pe,rows,s,ix,z,o,sb)
 rid=T&0xffffff;rp=o[6]+(rid-1)*z[6]
 if pe[rp:rp+z[6]].hex()!=ROW or mm.get(rid)!=('Weapon',''):raise E('MethodDef row/owner')
 rva=struct.unpack_from('<I',pe,rp)[0];p=rp+8;ni,p=rd(pe,p,s);si,p=rd(pe,p,b);plist,p=rd(pe,p,ix(8))
 if (rva,s_at(pe,sb,ni),blob(pe,bb,si).hex())!=(RVA,'Update_Falling',SIG):raise E('method metadata')
 nrp=o[6]+rid*z[6]+8;_,nrp=rd(pe,nrp,s);_,nrp=rd(pe,nrp,b);nplist,_=rd(pe,nrp,ix(8))
 if plist!=nplist:raise E('unexpected params')
 ho=off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,3,0):raise E('header')
 start,c=meth(pe,ss,RVA)
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 for il,op,tok in OPS:
  if c[il]!=op or struct.unpack_from('<I',c,il+1)[0]!=tok:raise E('IL '+hex(il))
 if c[0x3f]!=0x42 or (0x44+struct.unpack_from('<i',c,0x40)[0])!=0xA3:raise E('ground branch')
 if c[0x61]!=0x22 or struct.unpack_from('<f',c,0x62)[0] != struct.unpack('<f',bytes.fromhex('9a9999be'))[0]:raise E('bounce factor')
 if c[0x7c]!=0x22 or struct.unpack_from('<f',c,0x7d)[0] != struct.unpack('<f',bytes.fromhex('6f12033b'))[0]:raise E('settle threshold')
 if c[0x81]!=0x42 or (0x86+struct.unpack_from('<i',c,0x82)[0])!=0xA3:raise E('settle branch')
 for tok,(own,nm,sg,raw) in FIELDS.items():
  fr=tok&0xffffff;fp=o[4]+(fr-1)*z[4];q2=fp+2;fni,q2=rd(pe,q2,s);fsi,_=rd(pe,q2,b)
  if pe[fp:fp+z[4]].hex()!=raw or fm.get(fr)!=(own,'') or s_at(pe,sb,fni)!=nm or blob(pe,bb,fsi).hex()!=sg:raise E('field '+hex(tok))
 psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2
 for tok,(nm,sg,raw) in MEMBERS.items():
  rr=tok&0xffffff;mp=o[10]+(rr-1)*z[10];q3=mp+psz;mni,q3=rd(pe,q3,s);msi,_=rd(pe,q3,b)
  if pe[mp:mp+z[10]].hex()!=raw or s_at(pe,sb,mni)!=nm or blob(pe,bb,msi).hex()!=sg:raise E('member '+hex(tok))
 for i in range(len(c)-4):
  if c[i] in (0x28,0x6f) and (struct.unpack_from('<I',c,i+1)[0]>>24)==0x06:raise E('unexpected internal game call')
 crva,n,h,il,op=CALLER;cstart,cb=meth(pe,ss,crva)
 if len(cb)!=n or hashlib.sha256(cb).hexdigest()!=h or cb[il]!=op or struct.unpack_from('<I',cb,il+1)[0]!=T:raise E('caller')
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if sorted(actual)!=[(cstart+il,op)]:raise E('global caller map '+repr(actual))
 tstart,tb=meth(pe,ss,THROW_RVA)
 if len(tb)!=THROW_SIZE or hashlib.sha256(tb).hexdigest()!=THROW_SHA:raise E('ThrowIn identity')
 if cb[THROW_CALL_IL]!=0x28 or struct.unpack_from('<I',cb,THROW_CALL_IL+1)[0]!=THROW_TOKEN:raise E('ThrowIn caller')
 tactual=[];needle=struct.pack('<I',THROW_TOKEN)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   tactual.append((x,opc));pos=x+1
 if sorted(tactual)!=[(cstart+THROW_CALL_IL,0x28)]:raise E('ThrowIn caller map')
 return {'code_size':164,'code_sha256':SHA,'direct_reference_count':1,'direct_caller_method_count':1,'competing_update_throw_in_code_size':188,'competing_update_throw_in_direct_caller_method_count':1}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Weapon.Update_Falling':0,'Weapon.UpdateWeapon':0,'Weapon.Update_ThrowIn':0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip():raise E('CRC')
  names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=zf.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return {'weapon_update_falling_row_count':0,'weapon_update_weapon_row_count':0,'weapon_update_throw_in_row_count':0,'promoted_as_evidence':False}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPON_UPDATE_FALLING: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPON_UPDATE_FALLING: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
