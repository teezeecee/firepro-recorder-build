#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x060052F1;RVA=0x00325EA7;ROW='a75e32000000960842640a00634a0000603d';SIG='000002';FLAGS=0x0896
BODY=bytes.fromhex('28f05200067bf58700042a');SHA='c1bdb25bf14d1778175cda4ec73d358c1891fcc0a65d3b566308883ea29c40ff'
CHILD=0x060052F0;CHILD_SHA='076c5c279b25adcb3393894e49a79529bb680282eeac30b4d08826cacfe852a7'
FIELD=0x040087F5;FIELD_ROW='01009ad1050008000000';FIELD_SIG='0602'
EXPECTED=[
('0x06004AEF','0x0000','3dba758b8d9de56bff6a5ba05fd34fb112fcd2fd17353a138eea05858014de9e'),
('0x06004B65','0x0000','ac5bd6e06bc7d05f1d7ee9c98ceac6a1b2977018dbcf86cfe907dd7648953dad'),
('0x06004BF8','0x0000','1dfbf3c6356f45db0a83ac1e230dacb69ddbb80fccb1461cb5e5d647aa27cccd'),
('0x06004BF9','0x0000','7d1ab3fa18c77f08602676f68a5c11dd9337399da3fbd322636ca1863c81f5c3'),
('0x06004BFA','0x0000','05dbcda85d33e3578b76a40d85e690c854799958555e3ff2dca0ee09740a943e'),
('0x06004BFC','0x000B','d704280aa1f90ac5c229c55959e889d6cbb361e4e1eedae84e7085efe4a65bbf'),
('0x06004BFD','0x0000','a79d16ffa067e95c3a3ecf1a95068b152a8f9b388eafac73db1b389b4efe3a6f'),
('0x06004C04','0x0000','ccbe089140c1f497636b8b1535e3b86be453e670d52b8c18e083bac5e59a9120'),
('0x06004C28','0x0000','f7c8b6c8ffd0a9cc28a67a2fca1bc37b3b32945501780866eea43d27ef13e178'),
('0x06004C29','0x0000','e240a8682cffb41e6e377aa75c86ea960e78288a504f1165433b201497de70b2'),
('0x06004CAB','0x0000','71bed08ccf22a5f40dfe8f32a3ceb11ce9d78586e320185bc595c18a6bb126a4'),
('0x060050B8','0x0000','0adb9265d2f975075ccf2477ba81bc57a8f095bfa8ea849aa7805909ca97ac94')]
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva) if rva else (None,b'')
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,nm,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'get_Initialized',SIG,('SteamManager','')):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0x2e or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 if body[0]!=0x28 or struct.unpack_from('<I',body,1)[0]!=CHILD or body[5]!=0x7b or struct.unpack_from('<I',body,6)[0]!=FIELD or body[10]!=0x2a:raise E('exact flow')
 cr,rv,im,fl,name,sg,pl,ow,cs,cb=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
 if name!='get_Instance' or ow!=('SteamManager','') or hashlib.sha256(cb).hexdigest()!=CHILD_SHA:raise E('FACT-0213 child identity')
 fr=FIELD&0xffffff;p=o[4]+(fr-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
 if pe[p:p+z[4]].hex()!=FIELD_ROW or fm.get(fr)!=('SteamManager','') or ov.base.s_at(pe,sb,ni)!='m_bInitialized' or ov.base.blob(pe,bb,si).hex()!=FIELD_SIG:raise E('field')
 needle=struct.pack('<I',T);actual=[]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid
  mr,rv,im,fl,name,sg,pl,ow,cs,bd=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not bd:continue
  for opc in (0x28,0x6f,0x73,0x27):
   pat=bytes([opc])+needle;pos=0
   while True:
    x=bd.find(pat,pos)
    if x<0:break
    actual.append((f'0x{tok:08X}',f'0x{x:04X}',hashlib.sha256(bd).hexdigest(),opc));pos=x+1
  for pref,opc in ((b'\xfe\x06',0xfe06),(b'\xfe\x07',0xfe07)):
   pat=pref+needle;pos=0
   while True:
    x=bd.find(pat,pos)
    if x<0:break
    actual.append((f'0x{tok:08X}',f'0x{x:04X}',hashlib.sha256(bd).hexdigest(),opc));pos=x+1
 if len(actual)!=12 or any(x[3]!=0x28 for x in actual):raise E('reference surface '+repr(actual))
 got=sorted((a,b,c) for a,b,c,_ in actual)
 if got!=sorted(EXPECTED):raise E('reference map')
 return {'code_size':11,'code_sha256':SHA,'direct_reference_count':12,'direct_caller_method_count':12}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'SteamManager.get_Initialized':0,'SteamManager.get_Instance':0,'Network.Network_OnlineCheck':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_STEAMMANAGER_GET_INITIALIZED: PASS');return 0
 except Exception as e:
  print('PROVE_STEAMMANAGER_GET_INITIALIZED: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
