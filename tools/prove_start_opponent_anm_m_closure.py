#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
RVA=0x002DAF40
CODE_SIZE=462
CODE_SHA='e4d47db13c895255bbbd2d9d112427c93491b757a4bde1ee9543265724e1b566'
WITNESS_SHA='2c61df5bd859ed15755a4929bd3f403691667423ee33bb4d8520e86e12153713'
REQ={'FormAnimator.ReqBasicAnm','FormAnimator.ReqSlotAnm','FormAnimator.ReqSerialAnm','FormAnimator.ReqSkillAnm'}

class ProofError(RuntimeError): pass

def sha_path(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
 return h.hexdigest()

def sha_stream(f):
 h=hashlib.sha256()
 for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
 return h.hexdigest()

def sections(pe):
 peoff=struct.unpack_from('<I',pe,0x3c)[0]
 if pe[peoff:peoff+4]!=b'PE\0\0': raise ProofError('not PE')
 nsec=struct.unpack_from('<H',pe,peoff+6)[0]; optsz=struct.unpack_from('<H',pe,peoff+20)[0]; base=peoff+24+optsz
 out=[]
 for i in range(nsec):
  o=base+i*40; vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8); out.append((va,vs,rp,rs))
 return out

def rvaoff(pe,ss,rva):
 for va,vs,rp,rs in ss:
  if va<=rva<va+max(vs,rs): return rp+rva-va
 raise ProofError(f'RVA {rva:#x}')

def mcode(pe,ss,rva):
 o=rvaoff(pe,ss,rva); b=pe[o]
 if b&3==2: h=1; n=b>>2
 elif b&3==3:
  fs=struct.unpack_from('<H',pe,o)[0]; h=(fs>>12)*4; n=struct.unpack_from('<I',pe,o+4)[0]
 else: raise ProofError('bad IL header')
 return pe[o+h:o+h+n]

def tok(code,off,op,t,label):
 if code[off]!=op or struct.unpack_from('<I',code,off+1)[0]!=t: raise ProofError(label)

def brtarget(code,off): return off+5+struct.unpack_from('<i',code,off+1)[0]

def verify_dll(path):
 got=sha_path(path)
 if got!=DLL_SHA: raise ProofError('DLL SHA '+got)
 pe=Path(path).read_bytes(); ss=sections(pe); code=mcode(pe,ss,RVA)
 if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError('method body')
 tok(code,0x0000,0x7E,0x040061FA,'PlayerMan.inst #1')
 if code[0x0005]!=0x03: raise ProofError('arg1 load')
 tok(code,0x0006,0x6F,0x06005065,'GetPlObj arg1')
 tok(code,0x0018,0x7E,0x040061FA,'PlayerMan.inst #2')
 if code[0x001D]!=0x05: raise ProofError('arg3 load')
 tok(code,0x001E,0x6F,0x06005065,'GetPlObj arg3')
 tok(code,0x0036,0x7B,0x04005ED8,'BasicSkillID')
 if code[0x003B]!=0x16 or code[0x003C]!=0x15: raise ProofError('ReqBasic constants')
 tok(code,0x003D,0x6F,0x06004E6F,'ReqBasicAnm')
 checks=[
  (0x0049,0x7D,0x04005EEC,'reqAnmInit'),(0x0055,0x7D,0x04005EEA,'isAnmBoot'),
  (0x0061,0x7D,0x04005ED5,'currentFormIdx'),(0x0077,0x7D,0x04005ED7,'AnmHostPlayer'),
  (0x0088,0x7D,0x04005ED0,'CurrentSkill'),(0x0099,0x7D,0x04005EDC,'anmType'),
  (0x00A5,0x7D,0x04005ED1,'CurrentAnmIdx'),(0x00C7,0x7B,0x04007C97,'terrainColType'),
  (0x00CC,0x7D,0x04006004,'TerrainColType'),(0x00F3,0x7B,0x04007C9E,'anmEndState'),
  (0x00F8,0x7D,0x04005EE2,'AnimeEnd'),(0x00FE,0x7B,0x04006468,'ringKind'),
  (0x0129,0x7B,0x04005FEE,'Zone'),(0x017F,0x7D,0x0400604F,'isIgnoreTerrainCol'),
  (0x01BD,0x7B,0x04005FB0,'source PlDir'),(0x01C2,0x7D,0x04005FB0,'target PlDir'),
  (0x01C8,0x6F,0x06004EDF,'DropWeapon')]
 for x in checks: tok(code,*x)
 if code[0x00A4]!=0x04: raise ProofError('arg2 -> CurrentAnmIdx')
 branches=[(0x0104,0x3B,0x0115),(0x0110,0x40,0x011C),(0x0123,0x3B,0x0172),(0x012F,0x3B,0x0140),(0x013B,0x40,0x0147),(0x014E,0x40,0x0172),(0x015A,0x3B,0x016B),(0x0166,0x40,0x0172),(0x0178,0x39,0x0184),(0x018A,0x39,0x01C7)]
 for off,op,target in branches:
  if code[off]!=op or brtarget(code,off)!=target: raise ProofError(f'branch {off:#x}')
 return {'dll_sha256':got,'code_sha256':CODE_SHA,'code_size':len(code)}

def verify_r6(path):
 got=sha_path(path)
 if got!=R6_SHA: raise ProofError('R6 SHA '+got)
 with zipfile.ZipFile(path) as z:
  bad=z.testzip()
  if bad: raise ProofError('ZIP CRC '+bad)
  names=[n for n in z.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1: raise ProofError('event_trace count')
  name=names[0]
  with z.open(name) as f: esha=sha_stream(f)
  if esha!=EVENT_SHA: raise ProofError('event SHA '+esha)
  stack=[]; records=[]; pre=post=0; parentc=Counter(); childc=Counter(); rel=Counter()
  with z.open(name) as raw:
   rd=csv.DictReader(io.TextIOWrapper(raw,encoding='utf-8-sig',newline=''),delimiter='\t')
   for line,row in enumerate(rd,start=2):
    if row['phase']=='PRE':
     node={'line':line,'row':dict(row),'children':[],'parent':stack[-1] if stack else None,'post_line':0,'post':None}
     if stack: stack[-1]['children'].append(node)
     stack.append(node)
     if row['method']=='FormAnimator.StartOpponentAnmM': pre+=1
    elif row['phase']=='POST':
     if not stack: raise ProofError('POST without PRE')
     node=stack.pop(); node['post_line']=line; node['post']=dict(row)
     if node['row']['method']!=row['method'] or node['row']['instance']!=row['instance']: raise ProofError('non-LIFO')
     if row['method']!='FormAnimator.StartOpponentAnmM': continue
     post+=1; r=node['row']; p=node['parent']
     if not p: raise ProofError('unparented StartOpponentAnmM')
     parentc[p['row']['method']]+=1
     a=[x.strip() for x in r['args'].split('|')]
     if len(a)!=3: raise ProofError('arg count')
     req=[x for x in node['children'] if x['row']['method'] in REQ]
     drop=[x for x in node['children'] if x['row']['method']=='Player.DropWeapon']
     if len(req)!=1 or len(drop)!=1: raise ProofError('child count')
     q=req[0]; d=drop[0]; childc[q['row']['method']]+=1; childc[d['row']['method']]+=1
     rel['arg2_is_2']+=a[1]=='2'
     rel['arg3_parent_target']+=a[2]==p['row']['target']
     rel['arg1_req_owner']+=a[0]==q['row']['owner_slot']
     rel['arg1_drop_owner']+=a[0]==d['row']['owner_slot']
     rel['three_slots_distinct']+=len({r['owner_slot'],a[0],a[2]})==3
     rel['req_args_parent_basic']+=q['row']['args']==f"{r['BasicSkillID']} | False | -1"
     rel['req_target_arg3']+=q['row']['target']==a[2]
     rel['drop_host_parent_owner']+=d['row']['AnmHostPlayer']==r['owner_slot']
     rel['drop_basic_parent_basic']+=d['row']['BasicSkillID']==r['BasicSkillID']
     rel['drop_anmType_parent']+=d['row']['anmType']==r['anmType']
     rel['drop_bank_arg2']+=d['row']['bank']==a[1]
     rel['reqpost_to_drop_host_changed']+=q['post']['AnmHostPlayer']!=d['row']['AnmHostPlayer']
     records.append((node['line'],node['post_line'],p['line'],a[0],a[1],a[2],r['owner_slot'],r['target'],q['line'],q['post_line'],d['line'],d['post_line'],q['row']['owner_slot'],d['row']['owner_slot'],d['row']['AnmHostPlayer']))
  if stack: raise ProofError('unterminated trace')
 if pre!=68 or post!=68 or len(records)!=68: raise ProofError('call count')
 if parentc!=Counter({'FormAnimator.InitAnimation':68}): raise ProofError('parents')
 if childc!=Counter({'FormAnimator.ReqBasicAnm':68,'Player.DropWeapon':68}): raise ProofError('children')
 expected={'arg2_is_2':68,'arg3_parent_target':68,'arg1_req_owner':68,'arg1_drop_owner':68,'three_slots_distinct':68,'req_args_parent_basic':68,'req_target_arg3':54,'drop_host_parent_owner':68,'drop_basic_parent_basic':68,'drop_anmType_parent':68,'drop_bank_arg2':68,'reqpost_to_drop_host_changed':48}
 for k,v in expected.items():
  if rel[k]!=v: raise ProofError(f'{k}: {rel[k]} != {v}')
 witness=''.join('\t'.join(map(str,r))+'\n' for r in records).encode('ascii')
 wsha=hashlib.sha256(witness).hexdigest()
 if len(witness)!=4259 or wsha!=WITNESS_SHA: raise ProofError(f'witness {len(witness)} {wsha}')
 return {'r6_sha256':got,'event_trace_sha256':esha,'record_count':len(records),'witness_byte_count':len(witness),'witness_sha256':wsha}

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--dll',required=True); ap.add_argument('--r6',required=True); ap.add_argument('--out'); a=ap.parse_args()
 try:
  out={'dll':verify_dll(a.dll),'r6':verify_r6(a.r6)}
  if a.out: Path(a.out).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(out,indent=2,sort_keys=True)); print('PROVE_START_OPPONENT_ANM_M_CLOSURE: PASS'); return 0
 except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
  print('PROVE_START_OPPONENT_ANM_M_CLOSURE: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
