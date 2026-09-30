#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
RVA=0x002D9F40
CODE_SIZE=105
CODE_SHA='fe75cf6bc4bc9f8915c55ace5e83feb79f2e1cf78577756b04bd7f8843d36f16'
WITNESS_SHA='08e17ff201a4a670a28ea44cf44e1200cacb0659f4eb455a918ce1a13fb56d4f'

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
 q=struct.unpack_from('<I',pe,0x3c)[0]
 if pe[q:q+4]!=b'PE\0\0': raise ProofError('not PE')
 n=struct.unpack_from('<H',pe,q+6)[0]; osz=struct.unpack_from('<H',pe,q+20)[0]; s=q+24+osz
 out=[]
 for i in range(n):
  o=s+i*40; vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8); out.append((va,vs,rp,rs))
 return out

def rvaoff(pe,ss,rva):
 for va,vs,rp,rs in ss:
  if va<=rva<va+max(vs,rs): return rp+rva-va
 raise ProofError('RVA unmapped')

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
 if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError('ReqBasicAnm body')
 if code[0]!=0x02 or code[1]!=0x16: raise ProofError('AnmReqType prefix')
 tok(code,0x0002,0x7D,0x04005ECF,'AnmReqType')
 if code[0x0007]!=0x02 or code[0x0008]!=0x03: raise ProofError('BasicSkillID args')
 tok(code,0x0009,0x7D,0x04005ED8,'BasicSkillID')
 if code[0x000E]!=0x04: raise ProofError('rev arg')
 if code[0x000F]!=0x39 or brtarget(code,0x000F)!=0x0062: raise ProofError('rev branch')
 tok(code,0x0015,0x7B,0x04005EE9,'isCopiedOpponentDir')
 if code[0x001A]!=0x39 or brtarget(code,0x001A)!=0x0062: raise ProofError('copied-dir branch')
 tok(code,0x0020,0x7B,0x04005ECE,'plObj target')
 tok(code,0x0026,0x7B,0x04005ECE,'plObj source')
 tok(code,0x002B,0x7B,0x04005FB0,'host PlDir load')
 tok(code,0x0030,0x28,0x06004963,'host direction helper')
 tok(code,0x0035,0x7D,0x04005FB0,'host PlDir store')
 tok(code,0x003A,0x7E,0x040061FA,'PlayerMan.inst')
 if code[0x003F]!=0x05: raise ProofError('def_pl_idx arg')
 tok(code,0x0040,0x6F,0x06005065,'GetPlObj')
 tok(code,0x0047,0x28,0x0A00002A,'Unity Object op_Implicit')
 if code[0x004C]!=0x39 or brtarget(code,0x004C)!=0x0062: raise ProofError('def branch')
 tok(code,0x0053,0x7B,0x04005FB0,'def PlDir load')
 tok(code,0x0058,0x28,0x06004963,'def direction helper')
 tok(code,0x005D,0x7D,0x04005FB0,'def PlDir store')
 if code[0x0062]!=0x02: raise ProofError('InitAnmWork receiver')
 tok(code,0x0063,0x28,0x06004E6C,'InitAnmWork')
 if code[0x0068]!=0x2A: raise ProofError('ret')
 return {'dll_sha256':got,'code_size':len(code),'code_sha256':CODE_SHA}

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
  stack=[]; records=[]; pre=post=0; parents=Counter(); rel=Counter(); arg1s=set(); tuples=set(); child_patterns=Counter()
  with z.open(name) as raw:
   rd=csv.DictReader(io.TextIOWrapper(raw,encoding='utf-8-sig',newline=''),delimiter='\t')
   for line,row in enumerate(rd,start=2):
    if row['phase']=='PRE':
     node={'line':line,'row':dict(row),'children':[],'parent':stack[-1] if stack else None}
     if stack: stack[-1]['children'].append(node)
     stack.append(node)
     if row['method']=='FormAnimator.ReqBasicAnm': pre+=1
    elif row['phase']=='POST':
     if not stack: raise ProofError('POST without PRE')
     node=stack.pop()
     if node['row']['method']!=row['method'] or node['row']['instance']!=row['instance']: raise ProofError('non-LIFO')
     if row['method']!='FormAnimator.ReqBasicAnm': continue
     post+=1; r=node['row']; p=node['parent']; pm=p['row']['method'] if p else 'ROOT'; pl=p['line'] if p else 0
     parents[pm]+=1; child_patterns[tuple(x['row']['method'] for x in node['children'])]+=1
     a=[x.strip() for x in r['args'].split('|')]
     if len(a)!=3: raise ProofError('args')
     arg1s.add(a[0]); tuples.add(tuple(a))
     rel['post_eq_arg1']+=row['BasicSkillID']==a[0]
     rel['pre_eq_arg1']+=r['BasicSkillID']==a[0]
     rel['pre_changed']+=r['BasicSkillID']!=row['BasicSkillID']
     rel['false_m1']+=a[1]=='False' and a[2]=='-1'
     rel['true_target']+=a[1]=='True' and a[2]==r['target']
     rel['true_root']+=a[1]=='True' and pm=='ROOT'
     if pm=='FormAnimator.StartOpponentAnm':
      rel['so_count']+=1
      rel['so_arg1_parent_basic']+=a[0]==p['row']['BasicSkillID']
      rel['so_false_m1']+=a[1]=='False' and a[2]=='-1'
      rel['so_owner_parent_target']+=r['owner_slot']==p['row']['target']
     if pm=='FormAnimator.StartOpponentAnmM':
      rel['som_count']+=1
      rel['som_arg1_parent_basic']+=a[0]==p['row']['BasicSkillID']
      rel['som_false_m1']+=a[1]=='False' and a[2]=='-1'
     if pm=='FormAnimator.ReqSlotAnm':
      rel['slot_count']+=1
      rel['slot_false_m1']+=a[1]=='False' and a[2]=='-1'
      rel['slot_owner_same']+=r['owner_slot']==p['row']['owner_slot']
     records.append((node['line'],line,pm,pl,a[0],a[1],a[2],r['owner_slot'],r['target'],r['BasicSkillID'],row['BasicSkillID']))
  if stack: raise ProofError('unterminated trace')
 if pre!=5761 or post!=5761 or len(records)!=5761: raise ProofError('call count')
 if parents!=Counter({'ROOT':4391,'Player.TransitStateAfterAnm':590,'FormAnimator.StartOpponentAnm':585,'Player.PostprocessEachState':113,'FormAnimator.StartOpponentAnmM':68,'FormAnimator.ReqSlotAnm':14}): raise ProofError('parents')
 if child_patterns!=Counter({():5761}): raise ProofError('direct children')
 expected={'post_eq_arg1':5761,'pre_eq_arg1':167,'pre_changed':5594,'false_m1':5714,'true_target':47,'true_root':47,'so_count':585,'so_arg1_parent_basic':585,'so_false_m1':585,'so_owner_parent_target':585,'som_count':68,'som_arg1_parent_basic':68,'som_false_m1':68,'slot_count':14,'slot_false_m1':14,'slot_owner_same':14}
 for k,v in expected.items():
  if rel[k]!=v: raise ProofError(f'{k}: {rel[k]} != {v}')
 if len(arg1s)!=168 or len(tuples)!=201: raise ProofError('distinct argument counts')
 witness=''.join('\t'.join(map(str,r))+'\n' for r in records).encode('ascii')
 wsha=hashlib.sha256(witness).hexdigest()
 if len(witness)!=482616 or wsha!=WITNESS_SHA: raise ProofError(f'witness {len(witness)} {wsha}')
 return {'r6_sha256':got,'event_trace_sha256':esha,'record_count':len(records),'witness_byte_count':len(witness),'witness_sha256':wsha}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--r6',required=True);ap.add_argument('--out');a=ap.parse_args()
 try:
  result={'dll':verify_dll(a.dll),'r6':verify_r6(a.r6)}
  if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(result,indent=2,sort_keys=True));print('PROVE_REQ_BASIC_ANM_CLOSURE: PASS');return 0
 except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
  print('PROVE_REQ_BASIC_ANM_CLOSURE: FAIL');print(str(e));return 1
if __name__=='__main__': raise SystemExit(main())
