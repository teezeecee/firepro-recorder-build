#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06005066;RVA=0x00304B88;ROW='884b3000000086003a430a00d5d40200fe3a';SIG='200112a78808';FLAGS=0x0086
BODY=bytes.fromhex('160a3850000000027bff610004069a14280f00000a3939000000027bff610004069a7b2b6000047b156100041a4021000000027bff610004069a7b316000047bc6610004034009000000027bff610004069a2a0617580a06027bff6100048e693fa2ffffff142a')
SHA='9a4d894da22ead6979e399924710d5823a3a505447e40ef6b8c838c6e4b5123e'
EXT=0x0A00000F;EXT_ROW='d100000088500600b6480000';EXT_SIG='00020212691269'
FIELDS={
 0x040061FF:('PlayerMan','PlObj','0600b7f203000d210000','061d12a788'),
 0x0400602B:('Player','plController','0600f6e5030011380000','0612a7b8'),
 0x04006115:('PlayerController','kind','0600635101006b380000','0611a7b4'),
 0x04006031:('Player','plCont_NetCom','060049e603002f380000','0612a7f8'),
 0x040061C6:('PlayerController_Network','port','060064f70300100f0000','06119050')}
REF_DIGEST='c50055b67a32cc2fba819ec1c1e2bd555bebd543a466406f7e99677d0481cf91'
CALLER_DIGEST='529c4c3a546bb03ece175162a02d143ed3392c759a5889a0c3b8df278a7cd4d8'
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
    out.append({'caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
  for pat,opname in ((b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')):
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
 return out
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,nm,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'GetPlObjFromPadPort',SIG,('PlayerMan','')):raise E('method metadata')
 ho=ov.base.off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if fs!=0x3013 or struct.unpack_from('<H',pe,ho+2)[0]!=2 or struct.unpack_from('<I',pe,ho+8)[0]!=0x1100003A:raise E('fat header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 if member(pe,rows,s,b,z,o,sb,bb,EXT)!=(EXT_ROW,'op_Inequality',EXT_SIG):raise E('external inequality')
 for tok,(own,name,row,sigx) in FIELDS.items():
  fr=tok&0xffffff;p=o[4]+(fr-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=row or fm.get(fr)!=(own,'') or ov.base.s_at(pe,sb,ni)!=name or ov.base.blob(pe,bb,si).hex()!=sigx:raise E('field '+hex(tok))
 checks=[(0x0008,0x7b,0x040061FF),(0x0010,0x28,EXT),(0x001b,0x7b,0x040061FF),(0x0022,0x7b,0x0400602B),(0x0027,0x7b,0x04006115),(0x0033,0x7b,0x040061FF),(0x003a,0x7b,0x04006031),(0x003f,0x7b,0x040061C6),(0x004b,0x7b,0x040061FF),(0x0059,0x7b,0x040061FF)]
 for il,op,tok in checks:
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('IL '+hex(il))
 if body[0x002c]!=0x1a:raise E('raw kind 4')
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f):
   tok=struct.unpack_from('<I',body,i+1)[0]
   if tok>>24==0x06:raise E('unexpected MethodDef child')
 refs=refmap(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(refs)!=2 or len({x['caller_token'] for x in refs})!=1 or {x['opcode'] for x in refs}!={'callvirt'}:raise E('reference surface')
 d=hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 callers=sorted({x['caller_token'] for x in refs});cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 if [(x['caller_token'],x['call_il']) for x in refs]!=[('0x06004B48','0x0057'),('0x06004B48','0x016B')]:raise E('IsSyncInputData boundary')
 return {'code_size':103,'code_sha256':SHA,'direct_reference_count':2,'direct_caller_method_count':1,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerMan.GetPlObjFromPadPort':0,'Network.IsSyncInputData':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERMAN_GET_PLOBJ_FROM_PAD_PORT: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERMAN_GET_PLOBJ_FROM_PAD_PORT: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
