#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
TYPE_RID=2559;TYPE_ROW='01001000507a000000000000b827c8613950';EXT=0x27B8;T=0x0600503A;RVA=0x003006D8;ROW='d80630000000c600edc800005c480000ec3a';SIG='200001';FLAGS=0x00C6
BODY=bytes.fromhex('02167d1761000402167d186100042a');SHA='1fb22e770dcbf84240bd60523215799d14585f3c5de15394803c5bffb8944298'
FIELDS=[(0x04006117,'padOn','0611904c','0600f71f0200440c0000',0x02),(0x04006118,'padPush','0611904c','0600f66a0100440c0000',0x09)]
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,mm=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 tr,tn,te,tml,tme=ov.tmeta(pe,rows,s,ix,z,o,sb,TYPE_RID)
 if (tr,tn,te)!=(TYPE_ROW,'PlayerController_NoControl',EXT):raise E('type metadata')
 mr,rva,impl,flags,nm,sig,start,body=ov.mmeta(pe,ss,s,b,ix,z,o,sb,bb,T&0xffffff)
 if (mr,rva,impl,flags,nm,sig)!=(ROW,RVA,0,FLAGS,'Update',SIG) or not (tml<=T&0xffffff<tme):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0x3e or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,name,sg,raw,il in FIELDS:
  rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=raw or fm.get(rid)!=('PlayerController','') or ov.base.s_at(pe,sb,ni)!=name or ov.base.blob(pe,bb,si).hex()!=sg:raise E('field '+name)
  if body[il]!=0x7d or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('store '+name)
 needle=struct.pack('<I',T);hits=[]
 for pat in (b'\x28',b'\x6f',b'\x73',b'\x27',b'\xfe\x06',b'\xfe\x07'):
  pos=0
  while True:
   x=pe.find(pat+needle,pos)
   if x<0:break
   hits.append(x);pos=x+1
 if hits:raise E('direct refs '+repr(hits))
 return {'code_size':15,'code_sha256':SHA,'direct_reference_count':0,'field_store_count':2}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerController.Update':0,'PlayerController_NoControl.Update':0,'MatchMain.Update_EntranceScene':0,'MatchMain.Update_Match':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERCONTROLLER_NOCONTROL_UPDATE: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_NOCONTROL_UPDATE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
