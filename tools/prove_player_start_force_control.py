#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playerforcedcontroller_start_foce_control as child
base=child.ov.base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004F74;RVA=0x002F2E89;ROW='892e2f0000008600f9320a008dcc0200913a';SIG='20010111a804';FLAGS=0x0086
BODY=bytes.fromhex('02037dfa5f0004027b32600004036f3f5000062a');SHA='5f7e39e4415fbe3bb7d6ddf30d6f7eceda02db18649b443d4f44f0a07a291d49'
FIELDS={
0x04005FFA:('Player','forceControl','06008fe30300f8370000','0611a804',0x0002,'stfld'),
0x04006032:('Player','plForcedController','060057e6030034380000','0612a80c',0x0009,'ldfld')}
CHILD=0x0600503F;CHILD_SHA='ede6d069634bd8695534188e0ff9ca8fb6cd7a4669425c39b4407cd7c3327320'
TUTORIAL=0x0600503D;TUTORIAL_SHA='ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe'
PROCESS=0x0600503C;PROCESS_SHA='0e53fcf88961297caf1853917b18bd92786b40b340e2b81da12b5f1ac4447c54'
REF_DIGEST='44ad08326b234ca5a8d5a921fad79c66a37ed5cc4a82adb1e3f61147a399b402';CALLER_DIGEST='75fe7eae110dd770f572eb87d17cb99ef25cd0a75f70c5cb32d74572ab81a024'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=base.rd(pe,q,s);si,q=base.rd(pe,q,b);plist,q=base.rd(pe,q,ix(8));start,body=base.meth(pe,ss,rva) if rva else (None,b'')
 return raw.hex(),rva,impl,flags,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def field(pe,s,b,z,o,sb,bb,fm,tok):
 rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];raw=pe[p:p+z[4]];q=p+2;ni,q=base.rd(pe,q,s);si,_=base.rd(pe,q,b)
 return raw.hex(),fm.get(rid),base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex()
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
    out.append({'caller_token':f'0x{tok:08X}','caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']));return out
def internal_calls(body):
 out=[]
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f,0x73,0x27):
   tok=struct.unpack_from('<I',body,i+1)[0]
   if (tok>>24)==0x06:out.append((i,body[i],tok))
  elif body[i]==0xfe and i+5<len(body) and body[i+1] in (0x06,0x07):
   tok=struct.unpack_from('<I',body,i+2)[0]
   if (tok>>24)==0x06:out.append((i,0x100|body[i+1],tok))
 return out
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,name,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Start_ForceControl',SIG,('Player','')):raise E('method metadata')
 tp=o[2]+(2561-1)*z[2];tr=pe[tp:tp+z[2]];tq=tp+4;tni,tq=base.rd(pe,tq,s);tnsi,tq=base.rd(pe,tq,s)
 if tr.hex()!='01010000857a0000000000004503cb613e50' or base.s_at(pe,sb,tni)!='ForceCtrlEnum' or base.s_at(pe,sb,tnsi)!='':raise E('ForceCtrlEnum metadata')
 if pe[base.off(ss,RVA)]!=0x52:raise E('tiny header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,(own,nm,row,sg,il,opname) in FIELDS.items():
  if field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):raise E('field '+hex(tok))
  op=0x7d if opname=='stfld' else 0x7b
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field site '+hex(il))
 if body[1]!=0x03 or body[0x0d]!=0x03:raise E('argument source')
 if internal_calls(body)!=[(0x000e,0x6f,CHILD)]:raise E('internal child '+repr(internal_calls(body)))
 cr=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
 if cr[4]!='Start_FoceControl' or cr[7]!=('PlayerForcedController','') or len(cr[9])!=29 or hashlib.sha256(cr[9]).hexdigest()!=CHILD_SHA:raise E('child identity')
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(rr)!=18 or len({x['caller_token'] for x in rr})!=15:raise E('reference surface')
 ops={k:sum(1 for x in rr if x['opcode']==k) for k in ('call','callvirt','newobj','jmp','ldftn','ldvirtftn')}
 if ops!={'call':2,'callvirt':16,'newobj':0,'jmp':0,'ldftn':0,'ldvirtftn':0}:raise E('opcode counts '+repr(ops))
 d=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 callers=sorted({x['caller_token'] for x in rr});cd=hashlib.sha256(''.join(x+'\n' for x in callers).encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 tut=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,TUTORIAL)
 if tut[4]!='Update' or tut[7]!=('PlayerController_Tutorial','') or len(tut[9])!=352 or hashlib.sha256(tut[9]).hexdigest()!=TUTORIAL_SHA:raise E('tutorial identity')
 if tut[9][0x0025]!=0x6f or struct.unpack_from('<I',tut[9],0x0026)[0]!=T:raise E('tutorial start callsite')
 if tut[9][0x0035]!=0x6f or struct.unpack_from('<I',tut[9],0x0036)[0]!=0x06004F75:raise E('tutorial end callsite')
 if tut[9][0x010B]!=0x28 or struct.unpack_from('<I',tut[9],0x010C)[0]!=PROCESS:raise E('tutorial process callsite')
 pr=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,PROCESS)
 if pr[4]!='Process_Grapple' or pr[7]!=('PlayerController_Tutorial','') or len(pr[9])!=109 or hashlib.sha256(pr[9]).hexdigest()!=PROCESS_SHA or internal_calls(pr[9])!=[]:raise E('Process_Grapple identity')
 return {'code_size':20,'code_sha256':SHA,'direct_reference_count':18,'direct_caller_method_count':15,'reference_map_sha256':d,'next_leaf':'PlayerController_Tutorial.Process_Grapple'}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Player.Start_ForceControl':0,'PlayerForcedController.Start_FoceControl':0,'PlayerController_Tutorial.Update':0,'PlayerController_Tutorial.Process_Grapple':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYER_START_FORCE_CONTROL: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYER_START_FORCE_CONTROL: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
