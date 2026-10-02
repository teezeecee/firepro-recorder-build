#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import prove_weaponman_drop as prev
base=prev.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006AB8;RVA=0x00434C48;ROW='484c43000000860000cf0a0075370300a14d';SIG='20040111190c11a85c11a768';SHA='eac3737037ba8ea767d588f6988426f6fd38567d37400dda6e58cfdc20ccc25e'
BODY=bytes.fromhex('02282800000a6f5000000a146fa207000a02282800000a6f5000000a22000000002200000000220000a0c1220000a041287c490006288006000a6f5c00000a021928b76a0006027bd6b60004166f3d02000a02037dd4b6000402047dddb6000402057ddab60004020e047ddbb6000402283d00000a7dd7b600040222000000002200000000226f1203bb734400000a7dd8b6000402187dd5b6000402220000803f7dd9b600042a')
OPEN=[(0x06006AB7,0x00434C1A,'20010108',44,'9fd8e4c6ea0c03f75b3de3aabfbe56ed4bf2f902ffe76bb13f7f57dee7b2c1b3','Weapon','SetPattern'),(0x0600497C,0x002B109C,'00020c0c0c',30,'088e4cd8eb7a187b28b71251188f91e260b6c7189cf32a45b89f6cd38b1868dc','MatchRandom','Range')]
CALLER=('WeaponMan','Drop',0x06006AC9,0x0043541C,33,'edcc7cf0273d8a9e58e2e252323436fb039630779892b4c0e2e9654eddab7f76',0x1B,0x6F)
WF=['pre_line','post_line','tick','pre_seq','post_seq','owner_slot','instance','pre_weaponIdx','post_weaponIdx','args','parent_method','parent_pre_line','parent_post_line','parent_pre_seq','parent_post_seq'];WSHA='68958e0d08de846fdf50acf4f9710308c78bdd42a62ad3ef8eabe189dbc7ee7f'
class E(RuntimeError):pass
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=8171008 or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.sections(pe);streams,hs,rows,p=base.metadata(pe,ss,q);owners=base.build_method_owner(pe,streams,hs,rows,p);m=base.parse_method_row(pe,streams,hs,rows,p,T&0xffffff,owners)
 if (m['type'],m['name'],m['rva'],m['sig'],prev.method_row_hex(pe,streams,hs,rows,p,T))!=('Weapon','Drop',RVA,SIG,ROW) or prev.param_names(pe,streams,hs,rows,p,T)!=[(1,'p'),(2,'gy'),(3,'zone'),(4,'dir')]:raise E('metadata')
 code=base.method(pe,ss,RVA)
 if (code['format'],code['flags'],code['max_stack'],code['local_sig'],len(code['code']),hashlib.sha256(code['code']).hexdigest())!=('fat',0x13,5,0,167,SHA) or code['code']!=BODY:raise E('body')
 c=code['code']
 for o,t in [(48,0x0600497C),(65,0x06006AB7),(71,0x0400B6D6),(84,0x0400B6D4),(91,0x0400B6DD),(98,0x0400B6DA),(106,0x0400B6DB),(117,0x0400B6D7),(143,0x0400B6D8),(150,0x0400B6D5),(161,0x0400B6D9)]:
  if struct.unpack_from('<I',c,o+1)[0]!=t:raise E('operand '+hex(o))
 for tok,rva,sig,size,sha,owner,name in OPEN:
  x=base.parse_method_row(pe,streams,hs,rows,p,tok&0xffffff,owners);mc=base.method(pe,ss,rva)['code']
  if (x['type'],x['name'],x['rva'],x['sig'],len(mc),hashlib.sha256(mc).hexdigest())!=(owner,name,rva,sig,size,sha):raise E('open helper')
 needle=struct.pack('<I',T);refs=[]
 for rid in range(1,rows[6]+1):
  x=base.parse_method_row(pe,streams,hs,rows,p,rid,owners)
  if not x['rva']:continue
  try:mc=base.method(pe,ss,x['rva'])['code']
  except Exception:continue
  for i in range(len(mc)-4):
   if mc[i] in (0x28,0x6F) and mc[i+1:i+5]==needle:refs.append((x['type'],x['name'],0x06000000|rid,x['rva'],len(mc),hashlib.sha256(mc).hexdigest(),i,mc[i]))
 if refs!=[CALLER]:raise E('inbound map')
 return {'code_size':167,'code_sha256':SHA,'inbound_reference_count':1}
def verify_r6(path):
 if prev.sha_path(path)!=R6_SHA:raise E('R6 identity')
 with zipfile.ZipFile(path) as z:
  if z.testzip():raise E('ZIP CRC')
  name=[n for n in z.namelist() if Path(n).name=='event_trace.tsv'][0]
  with z.open(name) as f:
   if hashlib.sha256(f.read()).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  stack=[];nodes=[]
  with z.open(name) as raw:
   for line,row in enumerate(csv.DictReader(io.TextIOWrapper(raw,encoding='utf-8-sig',newline=''),delimiter='\t'),start=2):
    if row['phase']=='MARK':continue
    if row['phase']=='PRE':
     n={'line':line,'row':dict(row),'post':None,'post_line':None,'parent':stack[-1] if stack else None,'children':[]}
     if stack:stack[-1]['children'].append(n)
     stack.append(n);nodes.append(n)
    else:n=stack.pop();n['post']=dict(row);n['post_line']=line
 ws=[n for n in nodes if n['row']['method']=='Weapon.Drop'];recs=[]
 if len(ws)!=11:raise E('count')
 for n in ws:
  p=n['parent']
  if not p or p['row']['method']!='Player.DropWeapon' or n['children'] or n['row']['owner_slot']!=p['row']['owner_slot'] or n['row']['weaponIdx']!=n['post']['weaponIdx'] or n['row']['tick']!=p['row']['tick']:raise E('relation')
  recs.append([n['line'],n['post_line'],n['row']['tick'],n['row']['seq'],n['post']['seq'],n['row']['owner_slot'],n['row']['instance'],n['row']['weaponIdx'],n['post']['weaponIdx'],n['row']['args'],p['row']['method'],p['line'],p['post_line'],p['row']['seq'],p['post']['seq']])
 if Counter(r[9] for r in recs)!=Counter({'Vector3 | 1 | InRing | Left':8,'Vector3 | 1 | InRing | Right':3}):raise E('args')
 w=''.join('\t'.join(map(str,r))+'\n' for r in recs).encode();h=hashlib.sha256(w).hexdigest()
 if (len(w),h)!=(1482,WSHA):raise E('witness')
 return {'weapon_drop_count':11,'witness_byte_count':1482,'witness_sha256':h,'left_count':8,'right_count':3}
def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_WEAPON_DROP: PASS');return 0
 except Exception as e:print('PROVE_WEAPON_DROP: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
