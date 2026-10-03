#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
TYPE_RID=2557;TYPE_ROW='010010001e7a000000000000b827c5613350';EXT=0x27B8;T=0x06005035;RVA=0x003005EA;ROW='ea0530000000c600edc800005c480000e83a';SIG='200001';FLAGS=0x00C6
BODY=bytes.fromhex('027e00280004027bc5610004947d17610004027e01280004027bc5610004947d18610004027efa5e0004027b166100046f864e00067d196100042a');SHA='7e6adb5aef2f2ce9384861ba006f6c2604af02cd16a87c245b92b5dee816658f'
FIELDS=[
 (0x04002800,'GamePadMan','padOn','061d11904c','1600f71f0200e0190000'),
 (0x040061C5,'PlayerController_GamePad','port','06119050','060064f70300100f0000'),
 (0x04006117,'PlayerController','padOn','0611904c','0600f71f0200440c0000'),
 (0x04002801,'GamePadMan','padPush','061d11904c','1600f66a0100e0190000'),
 (0x04006118,'PlayerController','padPush','0611904c','0600f66a0100440c0000'),
 (0x04005EFA,'GrappleHost','inst','0612a760','160006220100a2370000'),
 (0x04006116,'PlayerController','plIdx','0608','06004964020001000000'),
 (0x04006119,'PlayerController','grappleResult','0612a75c','06000ad8030070380000')
]
HELPER=0x06004E86;HELPER_RVA=0x002DBC7D;HELPER_SIZE=25;HELPER_SHA='bf842a3657431d2f1f462688a7c150fe32593bd1a4db78283487cfcd576cedf0'
REMAIN=[(0x06005038,94,'6263d3075a2b1147709139a168d07a8b4f9b6773a41b67ff169759a6fe4482ed'),(0x0600503D,352,'ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe'),(0x0600502B,984,'6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9')]
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 tr,tn,te,tml,tme=ov.tmeta(pe,rows,s,ix,z,o,sb,TYPE_RID)
 if (tr,tn,te)!=(TYPE_ROW,'PlayerController_GamePad',EXT):raise E('type metadata')
 mr,rva,impl,flags,nm,sig,start,body=ov.mmeta(pe,ss,s,b,ix,z,o,sb,bb,T&0xffffff)
 if (mr,rva,impl,flags,nm,sig)!=(ROW,RVA,0,FLAGS,'Update',SIG) or not (tml<=T&0xffffff<tme):raise E('method metadata')
 if pe[ov.base.off(ss,RVA)]!=0xee or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,owner,name,sg,raw in FIELDS:
  rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=raw or fm.get(rid)!=(owner,'') or ov.base.s_at(pe,sb,ni)!=name or ov.base.blob(pe,bb,si).hex()!=sg:raise E('field '+name)
 checks=[(0x01,0x7e,0x04002800),(0x07,0x7b,0x040061C5),(0x0d,0x7d,0x04006117),(0x13,0x7e,0x04002801),(0x19,0x7b,0x040061C5),(0x1f,0x7d,0x04006118),(0x25,0x7e,0x04005EFA),(0x2b,0x7b,0x04006116),(0x30,0x6f,HELPER),(0x35,0x7d,0x04006119)]
 for il,op,tok in checks:
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('IL '+hex(il))
 internal=[]
 for i in range(len(body)-4):
  if body[i] in (0x28,0x6f):
   tok=struct.unpack_from('<I',body,i+1)[0]
   if tok>>24==0x06:internal.append((i,body[i],tok))
 if internal!=[(0x30,0x6f,HELPER)]:raise E('internal calls '+repr(internal))
 _,hr,_,_,hn,hsig,_,hb=ov.mmeta(pe,ss,s,b,ix,z,o,sb,bb,HELPER&0xffffff)
 if hr!=HELPER_RVA or hn!='GetGrappleResult_ForOfflineTest' or len(hb)!=HELPER_SIZE or hashlib.sha256(hb).hexdigest()!=HELPER_SHA:raise E('helper identity')
 needle=struct.pack('<I',T);hits=[]
 for pat in (b'\x28',b'\x6f',b'\x73',b'\x27',b'\xfe\x06',b'\xfe\x07'):
  pos=0
  while True:
   x=pe.find(pat+needle,pos)
   if x<0:break
   hits.append(x);pos=x+1
 if hits:raise E('direct refs '+repr(hits))
 for tok,size,h in REMAIN:
  _,_,_,_,_,_,_,bd=ov.mmeta(pe,ss,s,b,ix,z,o,sb,bb,tok&0xffffff)
  if len(bd)!=size or hashlib.sha256(bd).hexdigest()!=h:raise E('frontier '+hex(tok))
 return {'code_size':59,'code_sha256':SHA,'canonical_child_call_count':1,'direct_reference_count':0}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerController_GamePad.Update':0,'GrappleHost.GetGrappleResult_ForOfflineTest':0,'PlayerController.Update':0,'MatchMain.Update_EntranceScene':0,'MatchMain.Update_Match':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERCONTROLLER_GAMEPAD_UPDATE: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_GAMEPAD_UPDATE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
