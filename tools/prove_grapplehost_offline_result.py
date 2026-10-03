#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004E86;RVA=0x002DBC7D;ROW='7dbc2d000000860060200a008cb602000c3a';SIG='200112a75c08';FLAGS=0x0086
BODY=bytes.fromhex('03163f07000000031e3f02000000142a027bfc5e0004039a2a');SHA='bf842a3657431d2f1f462688a7c150fe32593bd1a4db78283487cfcd576cedf0'
FIELD=0x04005EFC;FIELD_ROW='06000ad80300f9330000';FIELD_SIG='061d12a75c'
CALLERS=[
 (0x06005029,'PlayerController_AI','Prepare',0x002FFB54,210,'c217a11dcecafe819b6af42c0015265302fd359ec62a1758dc35a935c8a2917d',0x31),
 (0x06005035,'PlayerController_GamePad','Update',0x003005EA,59,'7e6adb5aef2f2ce9384861ba006f6c2604af02cd16a87c245b92b5dee816658f',0x30)
]
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva)
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,nm,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'GetGrappleResult_ForOfflineTest',SIG,('GrappleHost','')):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0x66 or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 if body[2]!=0x3f or 7+struct.unpack_from('<i',body,3)[0]!=0x0e:raise E('lower branch')
 if body[9]!=0x3f or 14+struct.unpack_from('<i',body,10)[0]!=0x10:raise E('upper branch')
 fr=FIELD&0xffffff;p=o[4]+(fr-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
 if pe[p:p+z[4]].hex()!=FIELD_ROW or fm.get(fr)!=('GrappleHost','') or ov.base.s_at(pe,sb,ni)!='grappleResult' or ov.base.blob(pe,bb,si).hex()!=FIELD_SIG:raise E('field')
 if body[0x11]!=0x7b or struct.unpack_from('<I',body,0x12)[0]!=FIELD or body[0x17]!=0x9a:raise E('lookup')
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f) and (struct.unpack_from('<I',body,i+1)[0]>>24)==0x06:raise E('unexpected child call')
 expected=[]
 for tok,own,nm,rva,size,h,il in CALLERS:
  cr,rv,im,fl,name,sg,pl,ow,cs,cb=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if ow!=(own,'') or name!=nm or rv!=rva or len(cb)!=size or hashlib.sha256(cb).hexdigest()!=h:raise E('caller identity '+nm)
  if cb[il]!=0x6f or struct.unpack_from('<I',cb,il+1)[0]!=T:raise E('caller edge '+nm)
  expected.append((cs+il,0x6f))
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if sorted(actual)!=sorted(expected):raise E('caller map '+repr(actual))
 return {'code_size':25,'code_sha256':SHA,'direct_reference_count':2,'direct_caller_method_count':2}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'GrappleHost.GetGrappleResult_ForOfflineTest':0,'PlayerController_GamePad.Update':0,'PlayerController_AI.Prepare':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_GRAPPLEHOST_OFFLINE_RESULT: PASS');return 0
 except Exception as e:
  print('PROVE_GRAPPLEHOST_OFFLINE_RESULT: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
