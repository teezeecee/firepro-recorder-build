#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006AC7; RVA=0x004353DC; ROW='dc534300000086005acf0a005c480000ac4d'; SIG='200001'
LOCAL_SIG_TOKEN=0x1100003A; LOCAL_SIG='070108'
CALLEE=0x06006AC6; CALLEE_IL=0x0009
BODY=bytes.fromhex('160a380b000000020628c66a00060617580a061e3feeffffff2a')
SHA='3e9811a875cf2dd7f62779e8ecf7cedaaf32084fcdeec863aa8e829aaa3c6467'
CALLERS=[
 (0x002A8E98,353,'f604d7a67afc50f501ac9ba6067303e7f7c4cabe1840cd7039da6c21ff03f79d',0x0091,0x6F),
 (0x002AB3EC,1387,'984f158c2da0fa72e67938d2970400e4e59fd96be8a32c0b256ca80109cc29ac',0x0463,0x6F),
 (0x002AD660,920,'2ae0da4a7e54fd7f3a74034bad7db65239cbcfedbf76d9d48ae767e7c0fff92a',0x02B1,0x6F)
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
 ss,q=secs(pe);st,hs,rows,tp=mdstreams(pe,ss,q);s,b,ix,z,o=tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0]
 fm,mm=owner_maps(pe,rows,s,ix,z,o,sb)
 rid=T&0xffffff;rp=o[6]+(rid-1)*z[6]
 if pe[rp:rp+z[6]].hex()!=ROW or mm.get(rid)!=('WeaponMan',''):raise E('MethodDef row/owner')
 p=rp+8;ni,p=rd(pe,p,s);si,p=rd(pe,p,b);plist,p=rd(pe,p,ix(8))
 if s_at(pe,sb,ni)!='DeleteAllWeapons' or blob(pe,bb,si).hex()!=SIG:raise E('method metadata')
 nrp=o[6]+rid*z[6]+8;_,nrp=rd(pe,nrp,s);_,nrp=rd(pe,nrp,b);nplist,_=rd(pe,nrp,ix(8))
 if plist!=nplist:raise E('unexpected params')
 ho=off(pe,ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,2,LOCAL_SIG_TOKEN):raise E('header')
 _,c=meth(pe,ss,RVA)
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 lr=LOCAL_SIG_TOKEN&0xffffff;sp=o[17]+(lr-1)*z[17];bi,_=rd(pe,sp,b)
 if blob(pe,bb,bi).hex()!=LOCAL_SIG:raise E('local signature')
 if c[CALLEE_IL]!=0x28 or struct.unpack_from('<I',c,CALLEE_IL+1)[0]!=CALLEE:raise E('DeleteWeapon call')
 if c[:2]!=bytes.fromhex('160a') or c[2]!=0x38 or struct.unpack_from('<i',c,3)[0]!=11:raise E('loop init')
 if c[14:20]!=bytes.fromhex('0617580a061e') or c[20]!=0x3f or struct.unpack_from('<i',c,21)[0]!=-18 or c[25]!=0x2a:raise E('loop tail')
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
 return {'code_size':26,'code_sha256':SHA,'delete_weapon_call_il':'0x0009','direct_reference_count':3,'direct_caller_method_count':3}
def verify_r6(path):
 if sha_file(path)!=R6_SHA:raise E('R6 identity')
 wanted={'WeaponMan.DeleteAllWeapons':0,'MatchMain.ProceedNextRound':0,'MatchMain.Update':0,'MatchMainCp.Update':0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip():raise E('CRC')
  names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  bts=zf.read(names[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return {'weaponman_delete_all_weapons_row_count':0,'direct_caller_rows':0,'promoted_as_evidence':False}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPONMAN_DELETE_ALL_WEAPONS: PASS');return 0
 except Exception as e:
  print('PROVE_WEAPONMAN_DELETE_ALL_WEAPONS: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
