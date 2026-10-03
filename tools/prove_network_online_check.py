#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004B65;RVA=0x002C2C5C;ROW='5c2c2c000000960014100a00634a0000c337';SIG='000002';FLAGS=0x0096
BODY=bytes.fromhex('28f15200063a02000000162a28340e000a3a02000000162a172a');SHA='ac5bd6e06bc7d05f1d7ee9c98ceac6a1b2977018dbcf86cfe907dd7648953dad'
CHILD=0x060052F1;CHILD_SHA='c1bdb25bf14d1778175cda4ec73d358c1891fcc0a65d3b566308883ea29c40ff'
EXT=0x0A000E34;EXT_ROW='910f000059530700634a0000';EXT_SIG='000002'
REF_COUNT=22;CALLER_COUNT=16
REF_DIGEST='b3adc0cc33c4c6c00d6d6e95044da098b1acabe34f6055dee111af9a3e49a863';CALLER_DIGEST='7cd18ccf031bc7cd391d14885901accf25d342887966210b78d6150a4f856c38'
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
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'Network_OnlineCheck',SIG,('Network','')):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0x6a or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 if body[0]!=0x28 or struct.unpack_from('<I',body,1)[0]!=CHILD or body[0x0c]!=0x28 or struct.unpack_from('<I',body,0x0d)[0]!=EXT:raise E('calls')
 if body[5]!=0x3a or 10+struct.unpack_from('<i',body,6)[0]!=12 or body[17]!=0x3a or 22+struct.unpack_from('<i',body,18)[0]!=24:raise E('branches')
 cr,rv,im,fl,name,sg,pl,ow,cs,cb=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
 if name!='get_Initialized' or ow!=('SteamManager','') or hashlib.sha256(cb).hexdigest()!=CHILD_SHA:raise E('FACT-0214 child identity')
 if member(pe,rows,s,b,z,o,sb,bb,EXT)!=(EXT_ROW,'BLoggedOn',EXT_SIG):raise E('external MemberRef')
 refs=refmap(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(refs)!=REF_COUNT or len({x['caller_token'] for x in refs})!=CALLER_COUNT or {x['opcode'] for x in refs}!={'call'}:raise E('reference surface')
 d=hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference-map digest '+d)
 callers=sorted({x['caller_token'] for x in refs});cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller-set digest '+cd)
 sync=[x for x in refs if x['caller_token']=='0x06004B48']
 if len(sync)!=1 or sync[0]['call_il']!='0x000D' or sync[0]['caller_code_sha256']!='ac9ee661178e8c57fa83c0572a6bc65d650c99c1aff55185cc942f5e5c52c89d':raise E('IsSyncInputData boundary')
 return {'code_size':26,'code_sha256':SHA,'direct_reference_count':REF_COUNT,'direct_caller_method_count':CALLER_COUNT,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Network.Network_OnlineCheck':0,'SteamManager.get_Initialized':0,'Network.IsSyncInputData':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_NETWORK_ONLINE_CHECK: PASS');return 0
 except Exception as e:
  print('PROVE_NETWORK_ONLINE_CHECK: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
