#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weapon_update_falling as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
BASE_RID=2542;TYPE_RID=2556;TYPE_ROW='01001000047a000000000000b827c5613150';EXT=0x27B8
T=0x06005032;RVA=0x003005B8;ROW='b80530000000c600edc800005c480000e53a';SIG='200001';FLAGS=0x00C6
BODY=bytes.fromhex('2a');SHA='684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1'
SIB=[('PlayerController_External',0x06005032,1,SHA),('PlayerController_NoControl',0x0600503A,15,'1fb22e770dcbf84240bd60523215799d14585f3c5de15394803c5bffb8944298'),('PlayerController_GamePad',0x06005035,59,'7e6adb5aef2f2ce9384861ba006f6c2604af02cd16a87c245b92b5dee816658f'),('PlayerController_Network',0x06005038,94,'6263d3075a2b1147709139a168d07a8b4f9b6773a41b67ff169759a6fe4482ed'),('PlayerController_Tutorial',0x0600503D,352,'ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe'),('PlayerController_AI',0x0600502B,984,'6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9')]
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def tmeta(pe,rows,s,ix,z,o,sb,rid):
 extz=4 if max(rows.get(x,0) for x in (2,1,27))>=16384 else 2
 p=o[2]+(rid-1)*z[2];raw=pe[p:p+z[2]];q=p+4;ni,q=base.rd(pe,q,s);nsi,q=base.rd(pe,q,s);ext,q=base.rd(pe,q,extz);_,q=base.rd(pe,q,ix(4));ml,q=base.rd(pe,q,ix(6))
 nml=rows[6]+1
 if rid<rows[2]:
  q=o[2]+rid*z[2]+4;_,q=base.rd(pe,q,s);_,q=base.rd(pe,q,s);_,q=base.rd(pe,q,extz);_,q=base.rd(pe,q,ix(4));nml,_=base.rd(pe,q,ix(6))
 return raw.hex(),base.s_at(pe,sb,ni),ext,ml,nml
def mmeta(pe,ss,s,b,ix,z,o,sb,bb,rid):
 p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=base.rd(pe,q,s);si,q=base.rd(pe,q,b);_,q=base.rd(pe,q,ix(8));start,body=base.meth(pe,ss,rva)
 return raw.hex(),rva,impl,flags,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex(),start,body
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0]
 _,bn,_,_,_=tmeta(pe,rows,s,ix,z,o,sb,BASE_RID)
 tr,tn,te,tml,tme=tmeta(pe,rows,s,ix,z,o,sb,TYPE_RID)
 if bn!='PlayerController' or (tr,tn,te)!=(TYPE_ROW,'PlayerController_External',EXT) or (te&3)!=0 or (te>>2)!=BASE_RID:raise E('type metadata')
 mr,rva,impl,flags,nm,sig,start,body=mmeta(pe,ss,s,b,ix,z,o,sb,bb,T&0xffffff)
 if (mr,rva,impl,flags,nm,sig)!=(ROW,RVA,0,FLAGS,'Update',SIG) or not (tml<=T&0xffffff<tme):raise E('method metadata')
 if flags&0x0100 or (flags&0x0040)==0 or (flags&0x0080)==0:raise E('override flags')
 if pe[base.off(ss,RVA)]!=0x06 or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 needle=struct.pack('<I',T);hits=[]
 for pat in (b'\x28',b'\x6f',b'\x73',b'\x27',b'\xfe\x06',b'\xfe\x07'):
  pos=0
  while True:
   x=pe.find(pat+needle,pos)
   if x<0:break
   hits.append(x);pos=x+1
 if hits:raise E('direct refs '+repr(hits))
 found=[]
 for rid in range(1,rows[2]+1):
  _,typ,ext,ml,me=tmeta(pe,rows,s,ix,z,o,sb,rid)
  if (ext&3)!=0 or (ext>>2)!=BASE_RID:continue
  for mid in range(ml,me):
   _,_,_,fl,nm,sg,_,bd=mmeta(pe,ss,s,b,ix,z,o,sb,bb,mid)
   if nm=='Update' and sg==SIG and (fl&0x0040) and not (fl&0x0100):
    found.append((typ,0x06000000|mid,len(bd),hashlib.sha256(bd).hexdigest()))
 found.sort(key=lambda x:x[2])
 if found!=SIB:raise E('override frontier '+repr(found))
 return {'code_size':1,'code_sha256':SHA,'direct_reference_count':0,'concrete_override_count':6,'smallest_override':'PlayerController_External'}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerController.Update':0,'PlayerController_External.Update':0,'MatchMain.Update_EntranceScene':0,'MatchMain.Update_Match':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERCONTROLLER_EXTERNAL_UPDATE: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_EXTERNAL_UPDATE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
