#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006AC6; RVA=0x00435394; ROW='94534300000086004dcf0a009f490000ab4d'; SIG='20010108'
FIELD=0x0400B6EC; FIELD_ROW='0600aa4f06009d190000'; FIELD_SIG='061d12b508'
LOCAL_SIG_TOKEN=0x11001074; LOCAL_SIG='070112b508'
BODY=bytes.fromhex('03163f07000000031e3f010000002a027becb60004039a0a06282a00000a3a010000002a066f2800000a286f11000a027becb600040314a22a')
SHA='8855138052c3fa6baf7847766f20a3ff5ded2a517364b594dc4a7af747239be1'
MEMBERS={
 0x0A00002A:('d100000085510600e9490000','op_Implicit','0001021269'),
 0x0A000028:('0901000076510600df490000','get_gameObject','2000120d'),
 0x0A00116F:('d100000062b90700cc510000','DestroyObject','0001011269')
}
CALLERS=[
 (0x002E9D80,1272,'9b0ee15ab9d50d7c55f283494967415fb4b3ab70e096088cafdafba068efe313',0x013C,0x6F),
 (0x00434E20,92,'3aa49b941ea49de68211c6b8bd98672b796ea36dc5eb99deeae75ef911aa737d',0x0027,0x6F),
 (0x004353DC,26,'3e9811a875cf2dd7f62779e8ecf7cedaaf32084fcdeec863aa8e829aaa3c6467',0x0009,0x28)
]
class E(RuntimeError): pass
def sha_file(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''): h.update(c)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from('<I',pe,0x3c)[0];n=struct.unpack_from('<H',pe,q+6)[0];z=struct.unpack_from('<H',pe,q+20)[0];s=q+24+z
 return [(lambda o:(struct.unpack_from('<I',pe,o+12)[0],max(struct.unpack_from('<I',pe,o+8)[0],struct.unpack_from('<I',pe,o+16)[0]),struct.unpack_from('<I',pe,o+20)[0]))(s+i*40) for i in range(n)],q
def off(pe,ss,r):
 for a,n,p in ss:
  if a<=r<a+n:return p+r-a
 raise E('RVA '+hex(r))
def meth(pe,ss,r):
 o=off(pe,ss,r);b=pe[o]
 if b&3==2:return o+1,pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from('<H',pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',pe,o+4)[0]
 return o+h,pe[o+h:o+h+n]
def mdstreams(pe,ss,q):
 oo=q+24;dd=oo+(112 if struct.unpack_from('<H',pe,oo)[0]==0x20b else 96)
 cli=off(pe,ss,struct.unpack_from('<I',pe,dd+112)[0]);md=off(pe,ss,struct.unpack_from('<I',pe,cli+8)[0])
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
 ext=4 if max(rows.get(t,0) for t in (2,1,27))>=16384 else 2
 types=[]
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
 ss,q=secs(pe);st,hs,rows,tp=mdstreams(pe,ss,q);s,b,ix,z,o=tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0]
 fm,mm=owner_maps(pe,rows,s,ix,z,o,sb)
 rid=T&0xffffff;rp=o[6]+(rid-1)*z[6]
 if pe[rp:rp+z[6]].hex()!=ROW or mm.get(rid)!=('WeaponMan',''):raise E('MethodDef row/owner')
 p=rp+8;ni,p=rd(pe,p,s);si,p=rd(pe,p,b);plist,p=rd(pe,p,ix(8))
 if s_at(pe,sb,ni)!='DeleteWeapon' or blob(pe,bb,si).hex()!=SIG:raise E('method metadata')
 nrp=o[6]+rid*z[6]+8;_,nrp=rd(pe,nrp,s);_,nrp=rd(pe,nrp,b);nplist,_=rd(pe,nrp,ix(8))
 pars=[]
 for pr in range(plist,nplist):
  pp=o[8]+(pr-1)*z[8];seq=struct.unpack_from('<H',pe,pp+2)[0];pn,_=rd(pe,pp+4,s);pars.append((seq,s_at(pe,sb,pn)))
 if pars!=[(1,'idx')]:raise E('parameter')
 ho=off(pe,ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,3,LOCAL_SIG_TOKEN):raise E('header')
 _,c=meth(pe,ss,RVA)
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 if c[0:15]!=bytes.fromhex('03163f07000000031e3f010000002a'):raise E('bounds')
 fr=FIELD&0xffffff;fp=o[4]+(fr-1)*z[4]
 if pe[fp:fp+z[4]].hex()!=FIELD_ROW or fm.get(fr)!=('WeaponMan',''):raise E('field row/owner')
 q2=fp+2;fni,q2=rd(pe,q2,s);fsi,_=rd(pe,q2,b)
 if s_at(pe,sb,fni)!='WeaponObj' or blob(pe,bb,fsi).hex()!=FIELD_SIG:raise E('field')
 lr=LOCAL_SIG_TOKEN&0xffffff;sp=o[17]+(lr-1)*z[17];bi,_=rd(pe,sp,b)
 if blob(pe,bb,bi).hex()!=LOCAL_SIG:raise E('local signature')
 mpsz=4 if max(rows.get(t,0) for t in (2,1,26,6,27)) >= (1<<(16-3)) else 2
 for tok,(raw,name,sig) in MEMBERS.items():
  rr=tok&0xffffff;mp=o[10]+(rr-1)*z[10]
  if pe[mp:mp+z[10]].hex()!=raw:raise E('member row '+hex(tok))
  q3=mp;_,q3=rd(pe,q3,mpsz);mni,q3=rd(pe,q3,s);msi,_=rd(pe,q3,b)
  if s_at(pe,sb,mni)!=name or blob(pe,bb,msi).hex()!=sig:raise E('member identity '+hex(tok))
 expected=[]
 for rva,n,h,il,op in CALLERS:
  start,mc=meth(pe,ss,rva)
  if len(mc)!=n or hashlib.sha256(mc).hexdigest()!=h or mc[il]!=op or struct.unpack_from('<I',mc,il+1)[0]!=T:raise E('caller')
  expected.append((start+il,op))
 actual=[];needle=struct.pack('<I',T)
 for op in (0x28,0x6f):
  pat=bytes([op])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,op));pos=x+1
 if sorted(actual)!=sorted(expected):raise E('global caller map '+repr(actual))
 return {'code_size':57,'code_sha256':SHA,'direct_reference_count':3,'direct_caller_method_count':3}
def verify_r6(path):
 if sha_file(path)!=R6_SHA:raise E('R6 identity')
 wanted={'WeaponMan.DeleteWeapon':0,'Player.ProcessAttackHit_Normal':0,'Weapon.Update_Equipped':0,'WeaponMan.DeleteAllWeapons':0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip():raise E('CRC')
  names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=zf.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return {'weaponman_delete_weapon_row_count':0,'direct_caller_rows':0,'promoted_as_evidence':False}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPONMAN_DELETE_WEAPON: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPONMAN_DELETE_WEAPON: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
