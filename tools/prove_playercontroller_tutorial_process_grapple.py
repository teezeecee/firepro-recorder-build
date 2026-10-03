#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_start_force_control as parent
base=parent.base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x0600503C;RVA=0x00300718;ROW='1807300000008100bc3a0a005c480000ed3a';SIG='200001';FLAGS=0x0081
BODY=bytes.fromhex('027bc86100047bb75f00041f163b08000000021c7dc96100042a027bc86100047bff5f0004163e010000002a027bc86100047ba85f00047be75e00043a010000002a02257bc961000417597dc9610004027bc9610004163e010000002a021f107d1861000402177d176100042a')
SHA='0e53fcf88961297caf1853917b18bd92786b40b340e2b81da12b5f1ac4447c54'
HEADER='133003006d00000000000000'
FIELDS={
0x040061C8:('PlayerController_Tutorial','plObj','01004f1902005e190000','0612a788'),
0x04005FB7:('Player','State','06006e000000da370000','0611a828'),
0x040061C9:('PlayerController_Tutorial','atkWaitTimer','010069f7030001000000','0608'),
0x04005FFF:('Player','penaltyTime','0600dce3030001000000','0608'),
0x04005FA8:('Player','animator','0600c8ae0000cb370000','0612a754'),
0x04005EE7:('FormAnimator','isAnmPause','060067d7030008000000','0602'),
0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c'),
0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c')}
ACCESS=[
(0x0001,0x7b,0x040061C8),(0x0006,0x7b,0x04005FB7),(0x0014,0x7d,0x040061C9),
(0x001b,0x7b,0x040061C8),(0x0020,0x7b,0x04005FFF),(0x002d,0x7b,0x040061C8),
(0x0032,0x7b,0x04005FA8),(0x0037,0x7b,0x04005EE7),(0x0044,0x7b,0x040061C9),
(0x004b,0x7d,0x040061C9),(0x0051,0x7b,0x040061C9),(0x0060,0x7d,0x04006118),
(0x0067,0x7d,0x04006117)]
REF_DIGEST='d72bb74bca1d8cfd7f8f5dc147961879cb4a3712df3bc65d5c53895c0d22ef71'
CALLER_DIGEST='43e28eea2cc7a60d5d07a84a1817375e230d7747eab89d02b1f76f54efacd7a6'
TUTORIAL=0x0600503D;TUTORIAL_SHA='ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe'
START=0x06004F74;START_SHA='5f7e39e4415fbe3bb7d6ddf30d6f7eceda02db18649b443d4f44f0a07a291d49'
END=0x06004F75;END_SHA='4321518c766e7855fee13fe8c71e345755accee937ddefec62ce07a84efcb40f'
RATE=0x06004955;RATE_SHA='6899b69e72e4f0b5853a85c1cb3796e28442d2abbd4ca2378d72dd59ce7bba58'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
 needle=struct.pack('<I',T);out=[];pats=[(bytes([0x28])+needle,'call'),(bytes([0x6f])+needle,'callvirt'),(bytes([0x73])+needle,'newobj'),(bytes([0x27])+needle,'jmp'),(bytes([0xfe,0x06])+needle,'ldftn'),(bytes([0xfe,0x07])+needle,'ldvirtftn')]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid;raw,rva,impl,flags,name,sig,plist,owner,start,body=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not body:continue
  for pat,opname in pats:
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']));return out
def target4(body,il):
 return il+5+struct.unpack_from('<i',body,il+1)[0]
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,name,sig,plist,owner,start,body=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_Grapple',SIG,('PlayerController_Tutorial','')):raise E('method metadata')
 if pe[base.off(ss,RVA):base.off(ss,RVA)+12].hex()!=HEADER:raise E('fat header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,(own,nm,row,sg) in FIELDS.items():
  if parent.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):raise E('field '+hex(tok))
 for il,op,tok in ACCESS:
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field access '+hex(il))
 if parent.internal_calls(body)!=[]:raise E('unexpected MethodDef child '+repr(parent.internal_calls(body)))
 if not (body[0x000b]==0x1f and body[0x000c]==22 and body[0x000d]==0x3b and target4(body,0x000d)==0x001a):raise E('State 22 gate')
 if not (body[0x0013]==0x1c and body[0x0014]==0x7d):raise E('timer reset')
 if not (body[0x0025]==0x16 and body[0x0026]==0x3e and target4(body,0x0026)==0x002c):raise E('penalty gate')
 if not (body[0x003c]==0x3a and target4(body,0x003c)==0x0042):raise E('pause gate')
 if not (body[0x0049]==0x17 and body[0x004a]==0x59):raise E('timer decrement')
 if not (body[0x0056]==0x16 and body[0x0057]==0x3e and target4(body,0x0057)==0x005d):raise E('timer completion gate')
 if not (body[0x005e]==0x1f and body[0x005f]==16 and body[0x0066]==0x17):raise E('raw input values')
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if rr!=[{'caller_type':'PlayerController_Tutorial','caller_namespace':'','caller_method':'Update','caller_token':'0x0600503D','caller_rva':'0x00300794','caller_code_size':352,'caller_code_sha256':TUTORIAL_SHA,'call_il':'0x010B','opcode':'call'}]:raise E('reference surface '+repr(rr))
 d=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 cd=hashlib.sha256(('0x0600503D'+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 tut=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,TUTORIAL)
 if tut[4]!='Update' or tut[7]!=('PlayerController_Tutorial','') or len(tut[9])!=352 or hashlib.sha256(tut[9]).hexdigest()!=TUTORIAL_SHA:raise E('tutorial identity')
 expected=[(0x0025,0x6f,START),(0x0035,0x6f,END),(0x010b,0x28,T),(0x0122,0x28,RATE),(0x014e,0x28,RATE)]
 if parent.internal_calls(tut[9])!=expected:raise E('tutorial MethodDef children '+repr(parent.internal_calls(tut[9])))
 for tok,size,h in [(START,20,START_SHA),(END,19,END_SHA),(RATE,38,RATE_SHA)]:
  mm=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if len(mm[9])!=size or hashlib.sha256(mm[9]).hexdigest()!=h:raise E('canonical sibling identity '+hex(tok))
 return {'code_size':109,'code_sha256':SHA,'direct_reference_count':1,'direct_caller_method_count':1,'reference_map_sha256':d,'tutorial_internal_methoddef_reference_count':5}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerController_Tutorial.Process_Grapple':0,'PlayerController_Tutorial.Update':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERCONTROLLER_TUTORIAL_PROCESS_GRAPPLE: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_TUTORIAL_PROCESS_GRAPPLE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
