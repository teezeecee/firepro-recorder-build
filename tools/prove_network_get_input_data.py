#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004B49;RVA=0x002C1EB8;ROW='b81e2c0000008600170e0a003ab60200ba37';SIG='200111a5ac08';FLAGS=0x0086;LOCAL=0x11000FBB;LOCAL_SIG='07030811a5ac11a5ac'
BODY=bytes.fromhex('030a027b8a5a0004069a6f2c0e000a3a0a0000001201fe156b090002072a027b8a5a0004069a166f2d0e000a0c082a');SHA='cc873352d36cbd8a43a791fa41ddce1e8815f39b47564fa45f6645c3f53565bd'
FIELD=0x04005A8A;FIELD_ROW='010031ae0300ef330000';FIELD_SIG='061d1512090111a5ac';COUNT=0x0A000E2C;ITEM=0x0A000E2D
CALLER=0x06005038;CALLER_RVA=0x00300658;CALLER_SIZE=94;CALLER_SHA='6263d3075a2b1147709139a168d07a8b4f9b6773a41b67ff169759a6fe4482ed';CALL_IL=0x1A
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva)
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def member(pe,rows,s,b,z,o,sb,bb,tok):
 rid=tok&0xffffff;psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2;p=o[10]+(rid-1)*z[10];raw=pe[p:p+z[10]];q=p+psz;ni,q=ov.base.rd(pe,q,s);si,_=ov.base.rd(pe,q,b)
 return raw.hex(),ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex()
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,nm,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,nm,sig,owner)!=(ROW,RVA,0,FLAGS,'GetInputData',SIG,('Network','')):raise E('method metadata')
 ho=ov.base.off(ss,RVA)
 if (struct.unpack_from('<H',pe,ho)[0]&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,2,LOCAL):raise E('header')
 lr=LOCAL&0xffffff;lp=o[17]+(lr-1)*z[17];bi,_=ov.base.rd(pe,lp,b)
 if ov.base.blob(pe,bb,bi).hex()!=LOCAL_SIG:raise E('locals')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 fr=FIELD&0xffffff;p=o[4]+(fr-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
 if pe[p:p+z[4]].hex()!=FIELD_ROW or fm.get(fr)!=('Network','') or ov.base.s_at(pe,sb,ni)!='m_InputBuffer' or ov.base.blob(pe,bb,si).hex()!=FIELD_SIG:raise E('field')
 if member(pe,rows,s,b,z,o,sb,bb,COUNT)[1:]!=('get_Count','200008') or member(pe,rows,s,b,z,o,sb,bb,ITEM)[1:]!=('get_Item','2001130008'):raise E('memberrefs')
 for il,op,tok in [(0x03,0x7b,FIELD),(0x0A,0x6f,COUNT),(0x1F,0x7b,FIELD),(0x27,0x6f,ITEM)]:
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('IL '+hex(il))
 if body[0x0F]!=0x3a or 0x14+struct.unpack_from('<i',body,0x10)[0]!=0x1e:raise E('count branch')
 if body[0x16:0x18]!=b'\xfe\x15' or struct.unpack_from('<I',body,0x18)[0]!=0x0200096B:raise E('default PadData')
 internal=[]
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f):
   tok=struct.unpack_from('<I',body,i+1)[0]
   if tok>>24==0x06:internal.append((i,body[i],tok))
 if internal:raise E('internal calls '+repr(internal))
 cr,rv,im,fl,name,sg,pl,ow,cs,cb=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,CALLER)
 if ow!=('PlayerController_Network','') or name!='Update' or rv!=CALLER_RVA or len(cb)!=CALLER_SIZE or hashlib.sha256(cb).hexdigest()!=CALLER_SHA or cb[CALL_IL]!=0x6f or struct.unpack_from('<I',cb,CALL_IL+1)[0]!=T:raise E('caller')
 actual=[];needle=struct.pack('<I',T)
 for opc in (0x28,0x6f):
  pat=bytes([opc])+needle;pos=0
  while True:
   x=pe.find(pat,pos)
   if x<0:break
   actual.append((x,opc));pos=x+1
 if actual!=[(cs+CALL_IL,0x6f)]:raise E('caller map '+repr(actual))
 return {'code_size':47,'code_sha256':SHA,'direct_reference_count':1,'direct_caller_method_count':1}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Network.GetInputData':0,'PlayerController_Network.Update':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_NETWORK_GET_INPUT_DATA: PASS');return 0
 except Exception as e:
  print('PROVE_NETWORK_GET_INPUT_DATA: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
