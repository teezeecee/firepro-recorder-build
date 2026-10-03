#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006AC0;RVA=0x00435282;ROW='82524300000096003b7f080096370300a84d';SIG='000012b510';FIELD=0x0400B6EA;FIELD_SIG='0612b510';BODY=bytes.fromhex('7eeab600042a');SHA='8efdce8690337e223d2f0de688a62b433f4d6515c73fa84c203aadbca4f524fb'
CALLERS=[(0x0010D064,386,'7d8231de8b396ae2209938f3104bd31a271a1009ceb600276f47492872f47066',0x68),(0x0010D064,386,'7d8231de8b396ae2209938f3104bd31a271a1009ceb600276f47492872f47066',0x87),(0x0010D328,716,'377d58fe989ffa42ca0420eacc751c37c34e758004b7bd61e1e16faaa5e53162',0),(0x0010D600,529,'9a90ee6e931c2e7e58f746ae75c41d44998fb63a7da7dac8972b34f1d2284ecf',0),(0x0010D600,529,'9a90ee6e931c2e7e58f746ae75c41d44998fb63a7da7dac8972b34f1d2284ecf',0x10),(0x002DB718,364,'ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085',0x98),(0x00434C1A,44,'9fd8e4c6ea0c03f75b3de3aabfbe56ed4bf2f902ffe76bb13f7f57dee7b2c1b3',0x15),(0x00434E20,92,'3aa49b941ea49de68211c6b8bd98672b796ea36dc5eb99deeae75ef911aa737d',0x1c)]
class E(RuntimeError):pass
def sh(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def secs(pe):
 q=struct.unpack_from('<I',pe,0x3c)[0];n=struct.unpack_from('<H',pe,q+6)[0];z=struct.unpack_from('<H',pe,q+20)[0];s=q+24+z
 return [(lambda o: (struct.unpack_from('<I',pe,o+12)[0],max(struct.unpack_from('<I',pe,o+8)[0],struct.unpack_from('<I',pe,o+16)[0]),struct.unpack_from('<I',pe,o+20)[0]))(s+i*40) for i in range(n)],q
def off(ss,r):
 for a,n,p in ss:
  if a<=r<a+n:return p+r-a
 raise E('RVA')
def meth(pe,ss,r):
 o=off(ss,r);b=pe[o]
 if b&3==2:return o+1,pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from('<H',pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',pe,o+4)[0];return o+h,pe[o+h:o+h+n]
def mdstreams(pe,ss,q):
 oo=q+24;dd=oo+(112 if struct.unpack_from('<H',pe,oo)[0]==0x20b else 96);cli=off(ss,struct.unpack_from('<I',pe,dd+112)[0]);md=off(ss,struct.unpack_from('<I',pe,cli+8)[0]);vl=struct.unpack_from('<I',pe,md+12)[0];p=(md+16+vl+3)&~3;_,ns=struct.unpack_from('<HH',pe,p);p+=4;st={}
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
 s=4 if hs&1 else 2;g=4 if hs&2 else 2;b=4 if hs&4 else 2
 def ix(t):return 4 if rows.get(t,0)>=65536 else 2
 def cx(ts,k):return 4 if max(rows.get(t,0) for t in ts)>=(1<<(16-k)) else 2
 z={0:2+s+3*g,1:cx([0,26,35,1],2)+2*s,2:4+2*s+cx([2,1,27],2)+ix(4)+ix(6),3:ix(4),4:2+s+b,5:ix(6),6:8+s+b+ix(8),7:ix(8),8:4+s,9:ix(2)+cx([2,1,27],2),10:cx([2,1,26,6,27],3)+s+b,11:2+cx([4,8,23],2)+b,12:cx([6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43],5)+cx([6,10],3)+b,13:cx([4,8],1)+b,14:2+cx([2,6,32],2)+b,15:6+ix(2),16:4+ix(4),17:b};o={};c=p
 for i in range(18):
  if i in rows:o[i]=c;c+=z[i]*rows[i]
 return s,b,ix,z,o
def verify_dll(p):
 pe=Path(p).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=secs(pe);st,hs,rows,tp=mdstreams(pe,ss,q);sz,bz,ix,z,o=tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0]
 rid=T&0xffffff;ro=o[6]+(rid-1)*z[6]
 if pe[ro:ro+z[6]].hex()!=ROW:raise E('MethodDef row')
 pos=ro+8;ni,pos=rd(pe,pos,sz);si,pos=rd(pe,pos,bz);name=pe[sb+ni:pe.index(b'\0',sb+ni)].decode()
 if name!='GetInst' or blob(pe,bb,si).hex()!=SIG:raise E('method metadata')
 _,c=meth(pe,ss,RVA)
 if c!=BODY or hashlib.sha256(c).hexdigest()!=SHA:raise E('body')
 fr=FIELD&0xffffff;fo=o[4]+(fr-1)*z[4]+2;fni,fo=rd(pe,fo,sz);fsi,_=rd(pe,fo,bz);fn=pe[sb+fni:pe.index(b'\0',sb+fni)].decode()
 if fn!='inst' or blob(pe,bb,fsi).hex()!=FIELD_SIG:raise E('field')
 pat=bytes([0x28])+struct.pack('<I',T);hits=[]
 for r,n,h,i in CALLERS:
  co,mc=meth(pe,ss,r)
  if len(mc)!=n or hashlib.sha256(mc).hexdigest()!=h or mc[i:i+5]!=pat:raise E('caller '+hex(r)+' '+hex(i))
  hits.append(co+i)
 allhits=[];start=0
 while True:
  x=pe.find(pat,start)
  if x<0:break
  allhits.append(x);start=x+1
 if allhits!=sorted(hits):raise E('global call map '+repr(allhits))
 return {'code_size':6,'code_sha256':SHA,'direct_reference_count':8,'direct_caller_method_count':6}
def verify_r6(p):
 if sh(p)!=R6_SHA:raise E('R6 identity')
 want={'WeaponMan.GetInst':0,'FormAnimator.PlayAnimationSE':0,'FormRenderer.ApplySortingOrder':0,'FormRenderer.SetPrdItem':0,'FormRenderer.SetWeaponObj':0,'Weapon.SetPattern':0,'Weapon.Update_Equipped':0}
 with zipfile.ZipFile(p) as z:
  if z.testzip():raise E('CRC')
  n=[x for x in z.namelist() if Path(x).name=='event_trace.tsv'][0]
  with z.open(n) as f:
   if hashlib.sha256(f.read()).hexdigest()!=EVENT_SHA:raise E('trace identity')
  with z.open(n) as raw:
   for r in csv.DictReader(io.TextIOWrapper(raw,encoding='utf-8-sig',newline=''),delimiter='\t'):
    if r['method'] in want:want[r['method']]+=1
 if want!={'WeaponMan.GetInst':0,'FormAnimator.PlayAnimationSE':90916,'FormRenderer.ApplySortingOrder':0,'FormRenderer.SetPrdItem':0,'FormRenderer.SetWeaponObj':0,'Weapon.SetPattern':0,'Weapon.Update_Equipped':0}:raise E('R6 '+repr(want))
 return {'weaponman_get_inst_row_count':0,'play_animation_se_row_count':90916,'play_animation_se_execution_count':45458,'promoted_as_evidence':False}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPONMAN_GET_INST: PASS');return 0
 except Exception as e:print('PROVE_WEAPONMAN_GET_INST: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
