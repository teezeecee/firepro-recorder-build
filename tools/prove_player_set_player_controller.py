#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004EAC;RVA=0x002DE380;ROW='80e32d00000086006c70030072c40200303a';SIG='20010111a7b4';FLAGS=0x0086
BODY=bytes.fromhex('03450600000049000000050000001600000027000000380000005a000000386600000002027b2e6000047d2b600004385500000002027b2f6000047d2b600004384400000002027b306000047d2b600004383300000002027b316000047d2b600004382200000002027b2c6000047d2b600004381100000002027b2d6000047d2b60000438000000002a')
SHA='5dd13b1056dacf616fe2c9832bf85dbc4901c3911bfc2b75200c1f23b9301acb'
FIELDS={
0x0400602B:('plController','0600f6e5030011380000','0612a7b8'),
0x0400602C:('plCont_NoControl','060003e6030016380000','0612a7fc'),
0x0400602D:('plCont_External','060014e603001b380000','0612a7f0'),
0x0400602E:('plCont_Pad','060024e6030020380000','0612a7f4'),
0x0400602F:('plCont_AI','06002fe6030025380000','0612a7c0'),
0x04006030:('plCont_Tutorial','060039e603002a380000','0612a800'),
0x04006031:('plCont_NetCom','060049e603002f380000','0612a7f8')}
REF_DIGEST='59539d1a2da184455e68f1c4a254cb2ba24645dcf251f48b646ee6c1676ec5e5';CALLER_DIGEST='9a826bc7a67969b1c67eeeb20453a0cf8ee774d385bb1f93705af97b4286305a'
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
 needle=struct.pack('<I',T);out=[]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid;raw,rva,impl,flags,name,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not body:continue
  for op,nameop in ((0x28,'call'),(0x6f,'callvirt'),(0x73,'newobj'),(0x27,'jmp')):
   pat=bytes([op])+needle;pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':nameop});pos=x+1
  for pat,nameop in ((b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')):
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':nameop});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']));return out
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,nm,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'SetPlayerController',SIG,('Player','')):raise E('method metadata')
 ho=ov.base.off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if fs!=0x3013 or struct.unpack_from('<H',pe,ho+2)[0]!=2 or struct.unpack_from('<I',pe,ho+8)[0]!=0:raise E('header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 mapping={0:0x0400602C,1:0x0400602E,2:0x0400602F,3:0x04006030,4:0x04006031,5:0x0400602D}
 if body[0]!=0x03 or body[1]!=0x45 or struct.unpack_from('<I',body,2)[0]!=6:raise E('switch header')
 base=30;offs=list(struct.unpack_from('<6i',body,6))
 if [base+x for x in offs]!=[0x67,0x23,0x34,0x45,0x56,0x78]:raise E('switch targets')
 for rawv,il in [(1,0x23),(2,0x34),(3,0x45),(4,0x56),(0,0x67),(5,0x78)]:
  if body[il:il+2]!=b'\x02\x02' or body[il+2]!=0x7b or struct.unpack_from('<I',body,il+3)[0]!=mapping[rawv] or body[il+7]!=0x7d or struct.unpack_from('<I',body,il+8)[0]!=0x0400602B:raise E('case '+str(rawv))
 if body[0x1e]!=0x38 or (0x23+struct.unpack_from('<i',body,0x1f)[0])!=0x89 or body[0x89]!=0x2a:raise E('default/ret')
 for tok,(name,row,sigx) in FIELDS.items():
  rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=row or fm.get(rid)!=('Player','') or ov.base.s_at(pe,sb,ni)!=name or ov.base.blob(pe,bb,si).hex()!=sigx:raise E('field '+hex(tok))
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f) and struct.unpack_from('<I',body,i+1)[0]>>24==0x06:raise E('unexpected MethodDef child')
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(rr)!=25 or len({x['caller_token'] for x in rr})!=11:raise E('reference counts')
 if {x['opcode'] for x in rr}!={'call','callvirt'} or sum(x['opcode']=='call' for x in rr)!=4:raise E('opcode counts')
 d=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 callers=sorted({x['caller_token'] for x in rr});cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 sync=[x['call_il'] for x in rr if x['caller_token']=='0x06004B48']
 if sync!=['0x006F','0x0186']:raise E('IsSyncInputData boundary')
 return {'code_size':138,'code_sha256':SHA,'direct_reference_count':25,'direct_caller_method_count':11,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Player.SetPlayerController':0,'Network.IsSyncInputData':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYER_SET_PLAYER_CONTROLLER: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYER_SET_PLAYER_CONTROLLER: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
