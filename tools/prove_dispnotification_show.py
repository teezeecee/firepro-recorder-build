#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x060049C3;RVA=0x002B2C33;ROW='332c2b0000008600ee930100377b01008036';SIG='2002010e08';FLAGS=0x0086
BODY=bytes.fromhex('02282800000a176f0301000a027b46580004036f6303000a02047d4758000402177d455800042a');SHA='ce3eb15bbbe9c74bd34eb1405194a3556fbdfabec4a4c4cb4c53f72389a61a14'
MEMBERS={
 0x0A000028:('get_gameObject','0901000076510600df490000','2000120d'),
 0x0A000103:('SetActive','19000000a7590600f4490000','20010102'),
 0x0A000363:('set_text','99010000f764060079480000','2001010e')}
FIELDS={
 0x04005846:('text_Message','0100037003009f050000','061280cd'),
 0x04005847:('duration','0100d0a7000001000000','0608'),
 0x04005845:('State','01006e000000ef320000','0611a444')}
REF_DIGEST='1d5050de4c98c6eacfc0231b8ecfcbaeee541df288bc959a74430f8e9168bae3';CALLER_DIGEST='14959fdadc85181fe585afa86fad4ed99d8a1b2c11217deafc0f714f3f29e3cc'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva) if rva else (None,b'')
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def member(pe,rows,s,b,z,o,sb,bb,tok):
 rid=tok&0xffffff;psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2;p=o[10]+(rid-1)*z[10];raw=pe[p:p+z[10]];q=p+psz;ni,q=ov.base.rd(pe,q,s);si,_=ov.base.rd(pe,q,b)
 return raw.hex(),ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex()
def refmap(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
 needle=struct.pack('<I',T);out=[]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid
  raw,rva,impl,flags,name,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not body:continue
  for op,opname in ((0x28,'call'),(0x6f,'callvirt'),(0x73,'newobj'),(0x27,'jmp')):
   pat=bytes([op])+needle;pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
  for pat,opname in ((b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')):
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
 return out
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,nm,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'Show',SIG,('DispNotification','')):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0x9e or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for il,op,tok in [(0x01,0x28,0x0A000028),(0x07,0x6f,0x0A000103),(0x0d,0x7b,0x04005846),(0x13,0x6f,0x0A000363),(0x1a,0x7d,0x04005847),(0x21,0x7d,0x04005845)]:
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('IL '+hex(il))
 if body[0x20]!=0x17 or body[-1]!=0x2a:raise E('raw state/ret')
 for tok,(name,row,sigx) in MEMBERS.items():
  if member(pe,rows,s,b,z,o,sb,bb,tok)!=(row,name,sigx):raise E('member '+hex(tok))
 for tok,(name,row,sigx) in FIELDS.items():
  fr=tok&0xffffff;p=o[4]+(fr-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=row or fm.get(fr)!=('DispNotification','') or ov.base.s_at(pe,sb,ni)!=name or ov.base.blob(pe,bb,si).hex()!=sigx:raise E('field '+hex(tok))
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f) and struct.unpack_from('<I',body,i+1)[0]>>24==0x06:raise E('unexpected MethodDef child')
 refs=refmap(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(refs)!=6 or len({x['caller_token'] for x in refs})!=2 or {x['opcode'] for x in refs}!={'callvirt'}:raise E('reference surface')
 d=hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 callers=sorted({x['caller_token'] for x in refs});cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 sync=[x['call_il'] for x in refs if x['caller_token']=='0x06004B48']
 if sync!=['0x00A7','0x00C0','0x01C1','0x01ED']:raise E('IsSyncInputData boundary')
 return {'code_size':39,'code_sha256':SHA,'direct_reference_count':6,'direct_caller_method_count':2,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'DispNotification.Show':0,'Network.IsSyncInputData':0,'MatchDebug.Test_Notification':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_DISPNOTIFICATION_SHOW: PASS');return 0
 except Exception as e:
  print('PROVE_DISPNOTIFICATION_SHOW: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
