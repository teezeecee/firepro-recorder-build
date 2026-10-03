#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weapon_update_falling as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004F97;RVA=0x002F5A67;ROW='675a2f000000c601edc800005c480000a43a';SIG='200001';IMPL=0x0000;FLAGS=0x01C6
BODY=bytes.fromhex('2a');SHA='684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1'
CALLERS=[
 (0x06004935,'MatchMain','Update_EntranceScene',0x002AA570,822,'574be9a2193d91b436a4a241a5dee31bd03c08b32ca09d28dbdf4afd60990cde',0x006F),
 (0x06004936,'MatchMain','Update_Match',0x002AA8B4,1152,'b6841694e03be5ca4c73e966a13802de9fe7339ab63540ffdf5edaee96ea9dfe',0x0129)
]
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def method_meta(pe,ss,rows,s,b,ix,z,o,sb,bb,mm,tok):
 rid=tok&0xffffff;rp=o[6]+(rid-1)*z[6];raw=pe[rp:rp+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0]
 p=rp+8;ni,p=base.rd(pe,p,s);si,p=base.rd(pe,p,b);plist,p=base.rd(pe,p,ix(8));start,body=base.meth(pe,ss,rva)
 return {'rid':rid,'row':raw.hex(),'rva':rva,'impl':impl,'flags':flags,'name':base.s_at(pe,sb,ni),'sig':base.blob(pe,bb,si).hex(),'plist':plist,'owner':mm.get(rid),'start':start,'body':body}
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,mm=base.owner_maps(pe,rows,s,ix,z,o,sb)
 m=method_meta(pe,ss,rows,s,b,ix,z,o,sb,bb,mm,T)
 if (m['row'],m['owner'],m['rva'],m['name'],m['sig'],m['impl'],m['flags'])!=(ROW,('PlayerController',''),RVA,'Update',SIG,IMPL,FLAGS):raise E('method metadata')
 nrp=o[6]+m['rid']*z[6]+8;_,nrp=base.rd(pe,nrp,s);_,nrp=base.rd(pe,nrp,b);nplist,_=base.rd(pe,nrp,ix(8))
 if m['plist']!=nplist:raise E('params')
 ho=base.off(ss,RVA)
 if pe[ho]!=0x06:raise E('tiny header')
 if m['body']!=BODY or hashlib.sha256(m['body']).hexdigest()!=SHA:raise E('body')
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
 return {'code_size':1,'code_sha256':SHA,'method_attributes_raw':FLAGS,'direct_reference_count':2,'direct_caller_method_count':2,'runtime_dispatch_promoted':False}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerController.Update':0,'MatchMain.Update_EntranceScene':0,'MatchMain.Update_Match':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERCONTROLLER_UPDATE_BASE: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_UPDATE_BASE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
