#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import prove_weapon_drop as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06006AB7; RVA=0x00434C1A; ROW='1a4c430000008600f5ce0a009f490000a04d'; SIG='20010108'; SHA='9fd8e4c6ea0c03f75b3de3aabfbe56ed4bf2f902ffe76bb13f7f57dee7b2c1b3'
BODY=bytes.fromhex('7eeab60004282a00000a391c000000027bd6b6000428c06a0006027bd3b60004036fcd6a00066fad02000a2a')
GET_INST=(0x06006AC0,0x00435282,'000012b510','82524300000096003b7f080096370300a84d',6,'8efdce8690337e223d2f0de688a62b433f4d6515c73fa84c203aadbca4f524fb','WeaponMan','GetInst')
GET_SPRITE=(0x06006ACD,0x004355A0,'2002121511b50408','a05543000000860094cf0a00ed370300b94d',98,'38d479af573bd1d4c4f72ad8947250d2ef5e4353f720d8c431daa0e3551dfb35','WeaponMan','GetWeaponSprite')
CALLERS=[
('FormRenderer','SetPrdItem',0x06001F53,0x0010D328,716,'377d58fe989ffa42ca0420eacc751c37c34e758004b7bd61e1e16faaa5e53162',0x00A1,0x6F),
('FormRenderer','SetWeaponObj',0x06001F54,0x0010D600,529,'9a90ee6e931c2e7e58f746ae75c41d44998fb63a7da7dac8972b34f1d2284ecf',0x0104,0x6F),
('Weapon','Init',0x06006AB5,0x00434B64,133,'87c87a97c51e7dc67d90e8443b62cebbad9ad52c255f9fd2983926fd4954bbe8',0x002C,0x28),
('Weapon','Drop',0x06006AB8,0x00434C48,167,'eac3737037ba8ea767d588f6988426f6fd38567d37400dda6e58cfdc20ccc25e',0x0041,0x28),
('Weapon','ThrowIn',0x06006AB9,0x00434CFC,280,'23c35ec28a501e732d34f62b83dab6f4bd74257137cc413917967b48df1e265e',0x0041,0x28)]
class E(RuntimeError): pass

def sha_path(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''): h.update(c)
 return h.hexdigest()

def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
 ss,q=base.sections(pe); streams,hs,rows,p=base.metadata(pe,ss,q); idx=base.build_index(pe,streams,hs,rows,p)
 m=base.methoddef(pe,idx,T)
 if (m['owner'],m['name'],m['rva'],m['sig'],m['row'])!=('Weapon','SetPattern',RVA,SIG,ROW): raise E('metadata')
 if base.params(pe,idx,T,rows)!=[(1,'pat')]: raise E('params')
 md=base.method(pe,ss,RVA); c=md['code']
 if (md['format'],md['flags'],md['max_stack'],md['local_sig'],len(c),hashlib.sha256(c).hexdigest())!=('tiny',2,8,0,44,SHA) or c!=BODY: raise E('body')
 # ldsfld WeaponMan.inst; call Object.op_Implicit; brfalse ret
 if c[0]!=0x7E or struct.unpack_from('<I',c,1)[0]!=0x0400B6EA: raise E('inst read')
 if c[5]!=0x28 or struct.unpack_from('<I',c,6)[0]!=0x0A00002A: raise E('Object.op_Implicit')
 if c[10]!=0x39 or 10+5+struct.unpack_from('<i',c,11)[0]!=43: raise E('null gate')
 # this.sprRen = WeaponMan.GetInst().GetWeaponSprite(this.kind, pat)
 if c[15]!=0x02 or c[16]!=0x7B or struct.unpack_from('<I',c,17)[0]!=0x0400B6D6: raise E('sprRen read')
 if c[21]!=0x28 or struct.unpack_from('<I',c,22)[0]!=GET_INST[0]: raise E('GetInst call')
 if c[26]!=0x02 or c[27]!=0x7B or struct.unpack_from('<I',c,28)[0]!=0x0400B6D3 or c[32]!=0x03: raise E('kind/pat load')
 if c[33]!=0x6F or struct.unpack_from('<I',c,34)[0]!=GET_SPRITE[0]: raise E('GetWeaponSprite call')
 if c[38]!=0x6F or struct.unpack_from('<I',c,39)[0]!=0x0A0002AD or c[43]!=0x2A: raise E('set_sprite/ret')
 for tok,expect in [(0x0400B6EA,('WeaponMan','inst','0612b510')),(0x0400B6D6,('Weapon','sprRen','061280b1')),(0x0400B6D3,('Weapon','kind','0611b504'))]:
  if base.field(pe,idx,tok)!=expect: raise E('field '+hex(tok))
 for tok,expect in [(0x0A00002A,('UnityEngine.Object','op_Implicit','0001021269')),(0x0A0002AD,('UnityEngine.SpriteRenderer','set_sprite','2001011215'))]:
  if base.memberref(pe,idx,tok)!=expect: raise E('memberref '+hex(tok))
 for tok,rva,sig,row,size,sha,owner,name in (GET_INST,GET_SPRITE):
  x=base.methoddef(pe,idx,tok); mc=base.method(pe,ss,rva)['code']
  if (x['owner'],x['name'],x['rva'],x['sig'],x['row'],len(mc),hashlib.sha256(mc).hexdigest())!=(owner,name,rva,sig,row,size,sha): raise E('open helper '+hex(tok))
 needle=struct.pack('<I',T); refs=[]
 for rid in range(1,rows[6]+1):
  x=base.methoddef(pe,idx,0x06000000|rid)
  if not x['rva']: continue
  try: code=base.method(pe,ss,x['rva'])['code']
  except Exception: continue
  for i in range(len(code)-4):
   if code[i] in (0x28,0x6F) and code[i+1:i+5]==needle:
    refs.append((x['owner'],x['name'],0x06000000|rid,x['rva'],len(code),hashlib.sha256(code).hexdigest(),i,code[i]))
 if refs!=CALLERS: raise E('caller map '+repr(refs))
 return {'code_size':44,'code_sha256':SHA,'direct_reference_count':5,'direct_caller_method_count':5,'open_helper_count':2}

def verify_r6(path):
 if sha_path(path)!=R6_SHA: raise E('R6 identity')
 wanted=['Weapon.SetPattern','Weapon.Init','Weapon.ThrowIn','FormRenderer.SetPrdItem','FormRenderer.SetWeaponObj','Weapon.Drop']
 counts={k:0 for k in wanted}
 with zipfile.ZipFile(path) as z:
  if z.testzip(): raise E('ZIP CRC')
  names=[n for n in z.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1: raise E('event trace count')
  name=names[0]
  with z.open(name) as f:
   if hashlib.sha256(f.read()).hexdigest()!=EVENT_SHA: raise E('event trace identity')
  with z.open(name) as raw:
   for row in csv.DictReader(io.TextIOWrapper(raw,encoding='utf-8-sig',newline=''),delimiter='	'):
    if row['method'] in counts: counts[row['method']]+=1
 if counts!={'Weapon.SetPattern':0,'Weapon.Init':0,'Weapon.ThrowIn':0,'FormRenderer.SetPrdItem':0,'FormRenderer.SetWeaponObj':0,'Weapon.Drop':22}: raise E('R6 boundary '+repr(counts))
 return {'weapon_set_pattern_row_count':0,'weapon_drop_row_count':22,'weapon_drop_execution_count':11,'promoted_as_evidence':False}

def main():
 a=argparse.ArgumentParser(); a.add_argument('--dll',required=True); a.add_argument('--r6',required=True); x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True)); print('PROVE_WEAPON_SET_PATTERN: PASS'); return 0
 except Exception as e:
  print('PROVE_WEAPON_SET_PATTERN: FAIL'); print(str(e)); return 1
if __name__=='__main__': raise SystemExit(main())
