#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x060052F0;RVA=0x00325E80;ROW='805e32000000910835640a00d7e50200603d';SIG='000012aa44';FLAGS=0x0891
BODY=bytes.fromhex('7ef387000414280600000a391000000072f2f3087073d600000a28e303002b2a7ef38700042a');SHA='076c5c279b25adcb3393894e49a79529bb680282eeac30b4d08826cacfe852a7'
FIELD=0x040087F3;FIELD_ROW='11007fd10500963b0000';FIELD_SIG='0612aa44';EQ=0x0A000006;CTOR=0x0A0000D6;MS=0x2B0003E3;US=0x7008F3F2
CALLER=0x060052F1;CALLER_RVA=0x00325EA7;CALLER_SIZE=11;CALLER_SHA='c1bdb25bf14d1778175cda4ec73d358c1891fcc0a65d3b566308883ea29c40ff'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva)
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def member(pe,rows,s,b,z,o,sb,bb,tok):
 rid=tok&0xffffff;psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2;p=o[10]+(rid-1)*z[10];raw=pe[p:p+z[10]];q=p+psz;ni,q=ov.base.rd(pe,q,s);si,_=ov.base.rd(pe,q,b)
 return raw.hex(),ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex()
def us(pe,st,idx):
 p=st['#US'][0]+idx;x=pe[p]
 if x<128:n=x;p+=1
 elif x<192:n=((x&63)<<8)|pe[p+1];p+=2
 else:n=((x&31)<<24)|(pe[p+1]<<16)|(pe[p+2]<<8)|pe[p+3];p+=4
 raw=pe[p:p+n]
 return raw[:-1].decode('utf-16le') if n%2 else raw.decode('utf-16le')
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,nm,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'get_Instance',SIG,('SteamManager','')):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0x9a or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 fr=FIELD&0xffffff;p=o[4]+(fr-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
 if pe[p:p+z[4]].hex()!=FIELD_ROW or fm.get(fr)!=('SteamManager','') or ov.base.s_at(pe,sb,ni)!='s_instance' or ov.base.blob(pe,bb,si).hex()!=FIELD_SIG:raise E('field')
 if member(pe,rows,s,b,z,o,sb,bb,EQ)[1:]!=('op_Equality','00020212691269') or member(pe,rows,s,b,z,o,sb,bb,CTOR)[1:]!=('.ctor','2001010e'):raise E('memberrefs')
 for il,op,tok in [(0x00,0x7e,FIELD),(0x06,0x28,EQ),(0x15,0x73,CTOR),(0x1a,0x28,MS),(0x20,0x7e,FIELD)]:
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('IL '+hex(il))
 if body[0x0b]!=0x39 or 0x10+struct.unpack_from('<i',body,0x0c)[0]!=0x20:raise E('null branch')
 if body[0x10]!=0x72 or struct.unpack_from('<I',body,0x11)[0]!=US or us(pe,st,US&0xffffff)!='SteamManager':raise E('user string')
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f):
   tok=struct.unpack_from('<I',body,i+1)[0]
   if tok>>24==0x06:raise E('unexpected MethodDef child')
 cr,rv,im,fl,name,sg,pl,ow,cs,cb=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,CALLER)
 if ow!=('SteamManager','') or name!='get_Initialized' or rv!=CALLER_RVA or len(cb)!=CALLER_SIZE or hashlib.sha256(cb).hexdigest()!=CALLER_SHA or cb[0]!=0x28 or struct.unpack_from('<I',cb,1)[0]!=T:raise E('caller')
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if actual!=[(cs,0x28)]:raise E('caller map '+repr(actual))
 return {'code_size':38,'code_sha256':SHA,'direct_reference_count':1,'direct_caller_method_count':1}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'SteamManager.get_Instance':0,'SteamManager.get_Initialized':0}
 with zipfile.ZipFile(path) as zf:
  if zf.testzip():raise E('CRC')
  n=[x for x in zf.namelist() if Path(x).name=='event_trace.tsv']
  if len(n)!=1:raise E('event trace count')
  bts=zf.read(n[0])
  if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:raise E('event identity')
  for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
   if row['method'] in wanted:wanted[row['method']]+=1
 if any(wanted.values()):raise E('R6 boundary '+repr(wanted))
 return dict(wanted,promoted_as_evidence=False)
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_STEAMMANAGER_GET_INSTANCE: PASS');return 0
 except Exception as e:
  print('PROVE_STEAMMANAGER_GET_INSTANCE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
