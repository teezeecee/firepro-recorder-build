#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06005040;RVA=0x00300938;ROW='38093000000086007f400a005c480000ef3a';SIG='200001';FLAGS=0x0086
BODY=bytes.fromhex('02167dde61000402167de261000402177de36100042a');SHA='4bce19fe9959b584ef14908126404a2afd4c862fc4d271de03b82729964915a3'
FIELDS={
0x040061DE:('PlayerForcedController','mode','0100ffda0100f8370000','0611a804',0x0002,0),
0x040061E2:('PlayerForcedController','step','0100baf8030001000000','0608',0x0009,0),
0x040061E3:('PlayerForcedController','isComplete','0100bff8030008000000','0602',0x0010,1)}
REF_DIGEST='2c3426da596fc724458f6d3cdcc1e461081535933d89e2968b6dff0b9c190dec';CALLER_DIGEST='0c05f793b48ce953db504be8e309305e2f3850091bc2f0b88cf76e64b09014f4'
TUTORIAL=0x0600503D;TUTORIAL_SHA='ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe'
AI=0x0600502B;AI_SHA='6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9'
END_PARENT=0x06004F75;END_PARENT_SHA='4321518c766e7855fee13fe8c71e345755accee937ddefec62ce07a84efcb40f'
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
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'End_FoceControl',SIG,('PlayerForcedController','')):raise E('method metadata')
 ho=ov.base.off(ss,RVA)
 if pe[ho]!=0x5A:raise E('tiny header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,(own,nm,row,sg,il,val) in FIELDS.items():
  rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=row or fm.get(rid)!=(own,'') or ov.base.s_at(pe,sb,ni)!=nm or ov.base.blob(pe,bb,si).hex()!=sg:raise E('field '+hex(tok))
  expected=0x16 if val==0 else 0x17
  if body[il-1]!=expected or body[il]!=0x7d or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field site '+hex(il))
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f) and (struct.unpack_from('<I',body,i+1)[0]>>24)==0x06:raise E('unexpected MethodDef child')
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(rr)!=3 or len({x['caller_token'] for x in rr})!=2:raise E('reference counts')
 d=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 callers=sorted({x['caller_token'] for x in rr});cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 exp=[('0x06004F75','0x000D','callvirt'),('0x06005055','0x010B','call'),('0x06005055','0x012C','call')]
 if [(x['caller_token'],x['call_il'],x['opcode']) for x in rr]!=exp:raise E('caller map')
 tr=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,TUTORIAL); ar=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,AI); er=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,END_PARENT)
 if tr[4]!='Update' or tr[7]!=('PlayerController_Tutorial','') or len(tr[9])!=352 or hashlib.sha256(tr[9]).hexdigest()!=TUTORIAL_SHA:raise E('tutorial override')
 if ar[4]!='Update' or ar[7]!=('PlayerController_AI','') or len(ar[9])!=984 or hashlib.sha256(ar[9]).hexdigest()!=AI_SHA:raise E('ai override')
 if er[4]!='End_ForceControl' or len(er[9])!=19 or hashlib.sha256(er[9]).hexdigest()!=END_PARENT_SHA or er[9][0x000D]!=0x6f or struct.unpack_from('<I',er[9],0x000E)[0]!=T:raise E('End_ForceControl boundary')
 tcalls=[(0x0025,0x6f,0x06004F74),(0x0035,0x6f,0x06004F75),(0x010B,0x28,0x0600503C),(0x0122,0x28,0x06004955),(0x014E,0x28,0x06004955)]
 for il,op,tok in tcalls:
  if tr[9][il]!=op or struct.unpack_from('<I',tr[9],il+1)[0]!=tok:raise E('tutorial child site '+hex(il))
 return {'code_size':22,'code_sha256':SHA,'direct_reference_count':3,'direct_caller_method_count':2,'reference_map_sha256':d,'remaining_update_overrides':[352,984]}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerForcedController.End_FoceControl':0,'Player.End_ForceControl':0,'PlayerForcedController.MakeKeyData_ForceControl':0,'PlayerController_Tutorial.Update':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERFORCEDCONTROLLER_END_FOCE_CONTROL: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERFORCEDCONTROLLER_END_FOCE_CONTROL: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
