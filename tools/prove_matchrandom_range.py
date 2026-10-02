#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import prove_weapon_drop as pd
base=pd
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x0600497C; RVA=0x002B109C; ROW='9c102b0000009600b4620600c65100005f36'; SIG='00020c0c0c'; SHA='088e4cd8eb7a187b28b71251188f91e260b6c7189cf32a45b89f6cd38b1868dc'
BODY=bytes.fromhex('7e8e5700041758808e5700040203280408000a80905700047e905700042a')
CALLERS=[
('Bloodstain','Awake',0x060047E4,0x002903AC,122,'7feab173d550f7f6333591ea4ab2dc2a7790bea625d7b18c9e13c1be350a95c3',0x0016,0x28),
('Bloodstain','Awake',0x060047E4,0x002903AC,122,'7feab173d550f7f6333591ea4ab2dc2a7790bea625d7b18c9e13c1be350a95c3',0x0035,0x28),
('MatchMisc','CriticalCheck',0x06004949,0x002AEC54,678,'8df067018ec4101a6f4861d7fe438f0ea51a2b50b1f698a9b908698e72352466',0x0292,0x28),
('PlayerController_AI','CheckOkiteyaburi',0x06004FE0,0x002F99F4,184,'b00f5d5ef683b9c4b5714491b6dfd3a05d0fd23fc062099c98f25a47cb5ded23',0x00A4,0x28),
('Weapon','Init',0x06006AB5,0x00434B64,133,'87c87a97c51e7dc67d90e8443b62cebbad9ad52c255f9fd2983926fd4954bbe8',0x0056,0x28),
('Weapon','Drop',0x06006AB8,0x00434C48,167,'eac3737037ba8ea767d588f6988426f6fd38567d37400dda6e58cfdc20ccc25e',0x0030,0x28),
('Weapon','ThrowIn',0x06006AB9,0x00434CFC,280,'23c35ec28a501e732d34f62b83dab6f4bd74257137cc413917967b48df1e265e',0x0030,0x28)]
class E(RuntimeError):pass

def sha_path(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''): h.update(c)
 return h.hexdigest()

def method_row_hex(pe,streams,hs,rows,p,token):
 _,_,_,_,sizes,offs=base.setup_tables(pe,streams,hs,rows,p); rid=token&0xffffff; o=offs[6]+(rid-1)*sizes[6]; return pe[o:o+sizes[6]].hex()

def param_names(pe,streams,hs,rows,p,token):
 strsz,blobsz,ix,cix,sizes,offs=base.setup_tables(pe,streams,hs,rows,p); sb=streams['#Strings'][0]
 def s(i):
  if not i:return ''
  e=pe.index(b'\0',sb+i); return pe[sb+i:e].decode()
 rid=token&0xffffff; o=offs[6]+(rid-1)*sizes[6]; pos=o+8; _,pos=base.rd(pe,pos,strsz); _,pos=base.rd(pe,pos,blobsz); first,pos=base.rd(pe,pos,ix(8));
 if rid<rows[6]:
  no=offs[6]+rid*sizes[6]; np=no+8; _,np=base.rd(pe,np,strsz); _,np=base.rd(pe,np,blobsz); nxt,np=base.rd(pe,np,ix(8))
 else:nxt=rows[8]+1
 out=[]
 for pr in range(first,nxt):
  po=offs[8]+(pr-1)*sizes[8]; _,seq=struct.unpack_from('<HH',pe,po); ni,_=base.rd(pe,po+4,strsz); out.append((seq,s(ni)))
 return out

def field_meta(pe,streams,hs,rows,p,token,owners):
 strsz,blobsz,ix,cix,sizes,offs=base.setup_tables(pe,streams,hs,rows,p); sb=streams['#Strings'][0]; bb=streams['#Blob'][0]; rid=token&0xffffff; o=offs[4]+(rid-1)*sizes[4]; pos=o+2; ni,pos=base.rd(pe,pos,strsz); si,pos=base.rd(pe,pos,blobsz); e=pe.index(b'\0',sb+ni); return owners[rid],pe[sb+ni:e].decode(),base.blob(pe,bb,si).hex()

def build_field_owners(pe,streams,hs,rows,p):
 strsz,blobsz,ix,cix,sizes,offs=base.setup_tables(pe,streams,hs,rows,p); sb=streams['#Strings'][0]
 def s(i):
  if not i:return ''
  e=pe.index(b'\0',sb+i); return pe[sb+i:e].decode()
 t=[]
 for rid in range(1,rows[2]+1):
  o=offs[2]+(rid-1)*sizes[2]; pos=o+4; ni,pos=base.rd(pe,pos,strsz); nsi,pos=base.rd(pe,pos,strsz); _,pos=base.rd(pe,pos,cix([2,1,27],2)); fs,pos=base.rd(pe,pos,ix(4)); _,pos=base.rd(pe,pos,ix(6)); t.append((fs,(s(nsi)+'.' if s(nsi) else '')+s(ni)))
 out={}
 for i,(st,nm) in enumerate(t):
  en=t[i+1][0] if i+1<len(t) else rows[4]+1
  for r in range(st,en):out[r]=nm
 return out

def verify_dll(path):
 pe=Path(path).read_bytes();
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.sections(pe); streams,hs,rows,p=base.metadata(pe,ss,q); idx=base.build_index(pe,streams,hs,rows,p)
 m=base.methoddef(pe,idx,T)
 if (m['owner'],m['name'],m['rva'],m['sig'],m['row'])!=('MatchRandom','Range',RVA,SIG,ROW):raise E('metadata')
 if base.params(pe,idx,T,rows)!=[(1,'min'),(2,'max')]:raise E('params')
 md=base.method(pe,ss,RVA); c=md['code']
 if (md['format'],md['flags'],md['max_stack'],md['local_sig'],len(c),hashlib.sha256(c).hexdigest())!=('tiny',2,8,0,30,SHA) or c!=BODY:raise E('body')
 if c[0]!=0x7E or struct.unpack_from('<I',c,1)[0]!=0x0400578E or c[5:7]!=bytes([0x17,0x58]) or c[7]!=0x80 or struct.unpack_from('<I',c,8)[0]!=0x0400578E:raise E('randomCnt flow')
 if c[12:14]!=bytes([0x02,0x03]) or c[14]!=0x28 or struct.unpack_from('<I',c,15)[0]!=0x0A000804:raise E('Unity Range call')
 if c[19]!=0x80 or struct.unpack_from('<I',c,20)[0]!=0x04005790 or c[24]!=0x7E or struct.unpack_from('<I',c,25)[0]!=0x04005790 or c[29]!=0x2A:raise E('lastRand flow')
 if base.field(pe,idx,0x0400578E)!=('MatchRandom','randomCnt','0608'):raise E('randomCnt field')
 if base.field(pe,idx,0x04005790)!=('MatchRandom','lastRandNum_Float','060c'):raise E('lastRand field')
 if base.memberref(pe,idx,0x0A000804)!=('UnityEngine.Random','Range','00020c0c0c'):raise E('Unity Random Range member')
 needle=struct.pack('<I',T); refs=[]
 for rid in range(1,rows[6]+1):
  x=base.methoddef(pe,idx,0x06000000|rid)
  if not x['rva']:continue
  try: code=base.method(pe,ss,x['rva'])['code']
  except Exception:continue
  for i in range(len(code)-4):
   if code[i] in (0x28,0x6F) and code[i+1:i+5]==needle:refs.append((x['owner'],x['name'],0x06000000|rid,x['rva'],len(code),hashlib.sha256(code).hexdigest(),i,code[i]))
 if refs!=CALLERS:raise E('caller map '+repr(refs))
 return {'code_size':30,'code_sha256':SHA,'direct_reference_count':7,'direct_caller_method_count':6}

def verify_r6(path):
 if sha_path(path)!=R6_SHA:raise E('R6 identity')
 with zipfile.ZipFile(path) as z:
  if z.testzip():raise E('ZIP CRC')
  names=[n for n in z.namelist() if Path(n).name=='event_trace.tsv']
  if len(names)!=1:raise E('event trace count')
  name=names[0]
  with z.open(name) as f:
   if hashlib.sha256(f.read()).hexdigest()!=EVENT_SHA:raise E('event trace identity')
  count=0
  with z.open(name) as raw:
   for row in csv.DictReader(io.TextIOWrapper(raw,encoding='utf-8-sig',newline=''),delimiter='\t'):
    if 'MatchRandom.Range' in row['method']:count+=1
 if count!=0:raise E('unexpected R6 MatchRandom.Range rows')
 return {'matchrandom_range_row_count':0,'promoted_as_evidence':False}

def main():
 a=argparse.ArgumentParser();a.add_argument('--dll',required=True);a.add_argument('--r6',required=True);x=a.parse_args()
 try:print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_MATCHRANDOM_RANGE: PASS');return 0
 except Exception as e:print('PROVE_MATCHRANDOM_RANGE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
