#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004F75;RVA=0x002F2E9E;ROW='9e2e2f00000086000c330a005c480000923a';SIG='200001';FLAGS=0x0086
BODY=bytes.fromhex('02167dfa5f0004027b326000046f405000062a');SHA='4321518c766e7855fee13fe8c71e345755accee937ddefec62ce07a84efcb40f'
FIELDS={
0x04005FFA:('Player','forceControl','06008fe30300f8370000','0611a804',0x0002,0x7d),
0x04006032:('Player','plForcedController','060057e6030034380000','0612a80c',0x0009,0x7b)}
CHILD=0x06005040;CHILD_SHA='4bce19fe9959b584ef14908126404a2afd4c862fc4d271de03b82729964915a3'
REF_DIGEST='0d514dda57375578c8776e675b24e79cab34db6f1bca46569a65c9774c15d572';CALLER_DIGEST='bb386065dcc6a0f7ba33c97d1afb993a7db3487c1279a253558f5982b3079136'
START_PARENT=0x06004F74;START_PARENT_SHA='5f7e39e4415fbe3bb7d6ddf30d6f7eceda02db18649b443d4f44f0a07a291d49'
START_CHILD=0x0600503F;START_CHILD_SHA='ede6d069634bd8695534188e0ff9ca8fb6cd7a4669425c39b4407cd7c3327320'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva) if rva else (None,b'')
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
 needle=struct.pack('<I',T);out=[];pats=[(b'\x28'+needle,'call'),(b'\x6f'+needle,'callvirt'),(b'\x73'+needle,'newobj'),(b'\x27'+needle,'jmp'),(b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid;raw,rva,impl,flags,name,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not body:continue
  for pat,opname in pats:
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']));return out
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,name,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'End_ForceControl',SIG,('Player','')):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0x4E:raise E('tiny header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,(own,nm,row,sg,il,op) in FIELDS.items():
  rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=row or fm.get(rid)!=(own,'') or ov.base.s_at(pe,sb,ni)!=nm or ov.base.blob(pe,bb,si).hex()!=sg:raise E('field '+hex(tok))
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field site '+hex(il))
 if body[0x0001]!=0x16:raise E('raw zero')
 if body[0x000D]!=0x6f or struct.unpack_from('<I',body,0x000E)[0]!=CHILD:raise E('child site')
 cm=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
 if cm[7]!=('PlayerForcedController','') or cm[4]!='End_FoceControl' or hashlib.sha256(cm[9]).hexdigest()!=CHILD_SHA:raise E('FACT-0222 child identity')
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(rr)!=13 or len({x['caller_token'] for x in rr})!=12 or {x['opcode'] for x in rr}!={'callvirt'}:raise E('reference surface')
 d=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 callers=sorted({x['caller_token'] for x in rr});cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 if not any(x['caller_token']=='0x0600503D' and x['call_il']=='0x0035' for x in rr):raise E('Tutorial.Update boundary')
 sp=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,START_PARENT);sc=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,START_CHILD)
 if sp[4]!='Start_ForceControl' or len(sp[9])!=20 or hashlib.sha256(sp[9]).hexdigest()!=START_PARENT_SHA:raise E('Start parent')
 if sc[4]!='Start_FoceControl' or len(sc[9])!=29 or hashlib.sha256(sc[9]).hexdigest()!=START_CHILD_SHA:raise E('Start child')
 return {'code_size':19,'code_sha256':SHA,'canonical_child_method_count':1,'direct_reference_count':13,'direct_caller_method_count':12,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Player.End_ForceControl':0,'PlayerForcedController.End_FoceControl':0,'PlayerController_Tutorial.Update':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYER_END_FORCE_CONTROL: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYER_END_FORCE_CONTROL: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
