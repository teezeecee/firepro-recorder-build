#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x0600503F;RVA=0x0030091A;ROW='1a093000000086006d400a008dcc0200ee3a';SIG='20010111a804';FLAGS=0x0086
BODY=bytes.fromhex('02037dde61000402167de261000402167dee61000402167de36100042a');SHA='ede6d069634bd8695534188e0ff9ca8fb6cd7a4669425c39b4407cd7c3327320'
FIELDS={
0x040061DE:('PlayerForcedController','mode','0100ffda0100f8370000','0611a804',0x0002,'arg'),
0x040061E2:('PlayerForcedController','step','0100baf8030001000000','0608',0x0009,0),
0x040061EE:('PlayerForcedController','pauseByPrevPlayer','01007bf9030008000000','0602',0x0010,0),
0x040061E3:('PlayerForcedController','isComplete','0100bff8030008000000','0602',0x0017,0)}
PARENT=0x06004F74;PARENT_SHA='5f7e39e4415fbe3bb7d6ddf30d6f7eceda02db18649b443d4f44f0a07a291d49'
TUTORIAL=0x0600503D;TUTORIAL_SHA='ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe'
REF_DIGEST='cc0833949bedc40f2bba43b0438d602a91dc8946b1e6e94a4568799712eafe25';CALLER_DIGEST='18af17efd4c766049af7e0898bc6533726be47690a5d556c40b2397ac27d839a'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva) if rva else (None,b'')
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def field(pe,s,b,z,o,sb,bb,fm,tok):
 rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];raw=pe[p:p+z[4]];q=p+2;ni,q=ov.base.rd(pe,q,s);si,_=ov.base.rd(pe,q,b)
 return raw.hex(),fm.get(rid),ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex()
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
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Start_FoceControl',SIG,('PlayerForcedController','')):raise E('method metadata')
 extz=4 if max(rows.get(t,0) for t in (2,1,27))>=16384 else 2;tp=o[2]+(2561-1)*z[2];tr=pe[tp:tp+z[2]];tq=tp+4;tni,tq=ov.base.rd(pe,tq,s);tnsi,tq=ov.base.rd(pe,tq,s)
 if tr.hex()!='01010000857a0000000000004503cb613e50' or ov.base.s_at(pe,sb,tni)!='ForceCtrlEnum' or ov.base.s_at(pe,sb,tnsi)!='':raise E('ForceCtrlEnum metadata')
 if pe[ov.base.off(ss,RVA)]!=0x76:raise E('tiny header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,(own,nm,row,sg,il,val) in FIELDS.items():
  if field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):raise E('field '+hex(tok))
  if val=='arg':
   if body[il-1]!=0x03:
    raise E('argument source')
  else:
   if body[il-1]!=0x16:
    raise E('raw zero source')
  if body[il]!=0x7d or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field site '+hex(il))
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f) and (struct.unpack_from('<I',body,i+1)[0]>>24)==0x06:raise E('unexpected MethodDef child')
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(rr)!=1 or len({x['caller_token'] for x in rr})!=1 or rr[0]['opcode']!='callvirt':raise E('reference surface')
 d=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 cd=hashlib.sha256(('0x06004F74\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 pr=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,PARENT)
 if pr[4]!='Start_ForceControl' or pr[7]!=('Player','') or len(pr[9])!=20 or hashlib.sha256(pr[9]).hexdigest()!=PARENT_SHA:raise E('parent identity')
 if pr[9][0x000E]!=0x6f or struct.unpack_from('<I',pr[9],0x000F)[0]!=T:raise E('parent callsite')
 tr=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,TUTORIAL)
 if tr[4]!='Update' or tr[7]!=('PlayerController_Tutorial','') or len(tr[9])!=352 or hashlib.sha256(tr[9]).hexdigest()!=TUTORIAL_SHA:raise E('tutorial identity')
 if tr[9][0x0025]!=0x6f or struct.unpack_from('<I',tr[9],0x0026)[0]!=PARENT:raise E('tutorial parent callsite')
 return {'code_size':29,'code_sha256':SHA,'direct_reference_count':1,'direct_caller_method_count':1,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerForcedController.Start_FoceControl':0,'Player.Start_ForceControl':0,'PlayerController_Tutorial.Update':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERFORCEDCONTROLLER_START_FOCE_CONTROL: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERFORCEDCONTROLLER_START_FOCE_CONTROL: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
