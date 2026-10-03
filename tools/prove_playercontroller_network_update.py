#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06005038;RVA=0x00300658;ROW='580630000000c600edc800005c480000eb3a';SIG='200001';FLAGS=0x00C6
LOCALS=0x11001143;LOCAL_BLOB='070111a5ac'
BODY=bytes.fromhex('281e0a000a6f484b0006394e000000281e0a000a027bc66100046f494b00060a0212007bf25a00047d176100040212007bf35a00047d186100040212007bf15a00047dc761000402281e0a000a027b166100046f584b00067d196100042a');SHA='6263d3075a2b1147709139a168d07a8b4f9b6773a41b67ff169759a6fe4482ed'
EXT=0x0A000A1E;EXT_ROW='2c0d000071ee060058cd0000';EXT_SIG='00001300'
CHILDREN={
0x06004B48:('Network','IsSyncInputData','ac9ee661178e8c57fa83c0572a6bc65d650c99c1aff55185cc942f5e5c52c89d',[(0x0005,0x6f)]),
0x06004B49:('Network','GetInputData','cc873352d36cbd8a43a791fa41ddce1e8815f39b47564fa45f6645c3f53565bd',[(0x001A,0x6f)]),
0x06004B58:('Network','GetGrappleResult','96fe199528ac76a9fff0c97bc3756699c17bad16faee068b22be044a933242da',[(0x0053,0x6f)])}
FIELDS={
0x040061C6:('PlayerController_Network','port','060064f70300100f0000','06119050',[(0x0015,0x7b)]),
0x04005AF2:('PadData','PadOn','060087b2030001000000','0608',[(0x0023,0x7b)]),
0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c',[(0x0028,0x7d)]),
0x04005AF3:('PadData','PadPush','06008db2030001000000','0608',[(0x0030,0x7b)]),
0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c',[(0x0035,0x7d)]),
0x04005AF1:('PadData','Frame','060081b2030001000000','0608',[(0x003D,0x7b)]),
0x040061C7:('PlayerController_Network','frame','06008cd8030001000000','0608',[(0x0042,0x7d)]),
0x04006116:('PlayerController','plIdx','06004964020001000000','0608',[(0x004E,0x7b)]),
0x04006119:('PlayerController','grappleResult','06000ad8030070380000','0612a75c',[(0x0058,0x7d)])}
EMPTY_REF_SHA='4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e06ecb64b4a728a08c04f7d';EMPTY_CALLER_SHA='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
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
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Update',SIG,('PlayerController_Network','')):raise E('method metadata')
 ho=ov.base.off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if fs!=0x3013 or struct.unpack_from('<H',pe,ho+2)[0]!=3 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCALS:raise E('fat header')
 lsrid=LOCALS&0xffffff;lsp=o[17]+(lsrid-1)*z[17];lsi,_=ov.base.rd(pe,lsp,b)
 if ov.base.blob(pe,bb,lsi).hex()!=LOCAL_BLOB:raise E('local signature')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 if member(pe,rows,s,b,z,o,sb,bb,EXT)!=(EXT_ROW,'get_instance',EXT_SIG):raise E('external get_instance')
 for il in (0x0000,0x000F,0x0048):
  if body[il]!=0x28 or struct.unpack_from('<I',body,il+1)[0]!=EXT:raise E('get_instance site '+hex(il))
 if body[0x000A]!=0x39 or (0x000F+struct.unpack_from('<i',body,0x000B)[0])!=0x005D:raise E('sync false branch')
 for tok,(own,nm,h,sites) in CHILDREN.items():
  cr,rv,im,fl,cn,cs,pl,co,cstart,cb=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if co!=(own,'') or cn!=nm or hashlib.sha256(cb).hexdigest()!=h:raise E('child identity '+hex(tok))
  for il,op in sites:
   if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('child site '+hex(il))
 for tok,(own,nm,row,sg,sites) in FIELDS.items():
  rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=row or fm.get(rid)!=(own,'') or ov.base.s_at(pe,sb,ni)!=nm or ov.base.blob(pe,bb,si).hex()!=sg:raise E('field '+hex(tok))
  for il,op in sites:
   if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field site '+hex(il))
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if rr:raise E('direct refs '+repr(rr))
 d=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=EMPTY_REF_SHA:raise E('empty ref digest')
 cd=hashlib.sha256(b'').hexdigest()
 if cd!=EMPTY_CALLER_SHA:raise E('empty caller digest')
 return {'code_size':94,'code_sha256':SHA,'canonical_child_method_count':3,'direct_reference_count':0,'direct_caller_method_count':0,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerController_Network.Update':0,'Network.IsSyncInputData':0,'Network.GetInputData':0,'Network.GetGrappleResult':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERCONTROLLER_NETWORK_UPDATE: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_NETWORK_UPDATE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
