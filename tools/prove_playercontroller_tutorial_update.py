#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_tutorial_process_grapple as leaf

parent=leaf.parent
base=leaf.base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x0600503D
RVA=0x00300794
ROW='940730000000c600edc800005c480000ed3a'
SIG='200001'
FLAGS=0x00C6
HEADER='133003006001000000000000'
BODY=bytes.fromhex('02167d1761000402167d18610004027bc86100047bee5f00043911000000027bc86100041a6f744f000638db000000027bc86100046f754f0006027bc86100047caa5f00047b0900000a027cca6100047b5900000a22cdcccc3d58430e00000002257b176100041a607d17610004027bc86100047caa5f00047b0900000a027cca6100047b5900000a22cdcccc3d59410e00000002257b176100041e607d17610004027bc86100047caa5f00047b0a00000a027cca6100047b5a00000a22cdcccc3d58430e00000002257b1761000418607d17610004027bc86100047caa5f00047b0a00000a027cca6100047b5a00000a22cdcccc3d59410e00000002257b1761000417607d1761000402283c500006027bc86100047b49600004391c0000001f1e28554900063908000000021f207d18610004021f207d17610004027bc86100047b4c60000439130000001f1e28554900063907000000021e7d186100042a')
SHA='ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe'

TYPE_RID=2560
TYPE_ROW='010010006b7a000000000000b827c8613b50'
BASE_RID=2542
EXTENDS=0x27B8
BASE_UPDATE=0x06004F97
BASE_UPDATE_SHA='684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1'
AI_UPDATE=0x0600502B
AI_RVA=0x002FFC68
AI_SHA='6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9'

FIELDS={
0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c'),
0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c'),
0x040061C8:('PlayerController_Tutorial','plObj','01004f1902005e190000','0612a788'),
0x04005FEE:('Player','Zone','0600dde203009f300000','0611a85c'),
0x04005FAA:('Player','PlPos','060039e0030070000000','061119'),
0x040061CA:('PlayerController_Tutorial','HomePos','060076f70300cb000000','061131'),
0x04006049:('Player','isPinfallDef','060071e7030008000000','0602'),
0x0400604C:('Player','isSubmissionDef','06009ce7030008000000','0602')
}
MEMBERS={
0x0A000009:('x','31000000dfb6000014000000','060c'),
0x0A00000A:('y','31000000e1b6000014000000','060c'),
0x0A000059:('x','61000000dfb6000014000000','060c'),
0x0A00005A:('y','61000000e1b6000014000000','060c')
}
ACCESS=[
(0x0002,'stfld',0x04006117),(0x0009,'stfld',0x04006118),(0x000F,'ldfld',0x040061C8),(0x0014,'ldfld',0x04005FEE),
(0x001F,'ldfld',0x040061C8),(0x0030,'ldfld',0x040061C8),(0x003B,'ldfld',0x040061C8),(0x0040,'ldflda',0x04005FAA),
(0x0045,'ldfld',0x0A000009),(0x004B,'ldflda',0x040061CA),(0x0050,'ldfld',0x0A000059),(0x0062,'ldfld',0x04006117),
(0x0069,'stfld',0x04006117),(0x006F,'ldfld',0x040061C8),(0x0074,'ldflda',0x04005FAA),(0x0079,'ldfld',0x0A000009),
(0x007F,'ldflda',0x040061CA),(0x0084,'ldfld',0x0A000059),(0x0096,'ldfld',0x04006117),(0x009D,'stfld',0x04006117),
(0x00A3,'ldfld',0x040061C8),(0x00A8,'ldflda',0x04005FAA),(0x00AD,'ldfld',0x0A00000A),(0x00B3,'ldflda',0x040061CA),
(0x00B8,'ldfld',0x0A00005A),(0x00CA,'ldfld',0x04006117),(0x00D1,'stfld',0x04006117),(0x00D7,'ldfld',0x040061C8),
(0x00DC,'ldflda',0x04005FAA),(0x00E1,'ldfld',0x0A00000A),(0x00E7,'ldflda',0x040061CA),(0x00EC,'ldfld',0x0A00005A),
(0x00FE,'ldfld',0x04006117),(0x0105,'stfld',0x04006117),(0x0111,'ldfld',0x040061C8),(0x0116,'ldfld',0x04006049),
(0x012F,'stfld',0x04006118),(0x0137,'stfld',0x04006117),(0x013D,'ldfld',0x040061C8),(0x0142,'ldfld',0x0400604C),
(0x015A,'stfld',0x04006118)
]
FIELD_ACCESS_DIGEST='c4011f423dd22a5bd5030ec5d1d0ac332605ed8ecbd5d25b186d00d3bc58f045'
EXPECTED_CALLS=[
(0x0025,0x6F,0x06004F74),
(0x0035,0x6F,0x06004F75),
(0x010B,0x28,0x0600503C),
(0x0122,0x28,0x06004955),
(0x014E,0x28,0x06004955)
]
REF_DIGEST='4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
CALLER_DIGEST='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

class E(RuntimeError):pass

def sh(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()

def typedef(pe,rows,s,ix,z,o,sb,rid):
 extz=4 if max(rows.get(x,0) for x in (2,1,27))>=16384 else 2
 p=o[2]+(rid-1)*z[2]
 raw=pe[p:p+z[2]]
 q=p+4
 ni,q=base.rd(pe,q,s)
 nsi,q=base.rd(pe,q,s)
 ext,q=base.rd(pe,q,extz)
 fl,q=base.rd(pe,q,ix(4))
 ml,q=base.rd(pe,q,ix(6))
 return raw.hex(),base.s_at(pe,sb,ni),base.s_at(pe,sb,nsi),ext,fl,ml

def member(pe,rows,s,b,z,o,sb,bb,tok):
 rid=tok&0xffffff
 psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2
 p=o[10]+(rid-1)*z[10]
 raw=pe[p:p+z[10]]
 q=p+psz
 ni,q=base.rd(pe,q,s)
 si,q=base.rd(pe,q,b)
 return raw.hex(),base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex()

def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
 needle=struct.pack('<I',T)
 pats=[(bytes([0x28])+needle,'call'),(bytes([0x6f])+needle,'callvirt'),(bytes([0x73])+needle,'newobj'),(bytes([0x27])+needle,'jmp'),(bytes([0xfe,0x06])+needle,'ldftn'),(bytes([0xfe,0x07])+needle,'ldvirtftn')]
 out=[]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid
  raw,rva,impl,flags,name,sig,plist,owner,start,body=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not body:continue
  for pat,opname in pats:
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_token':f'0x{tok:08X}','caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname})
    pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
 return out

def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe)
 st,hs,rows,tp=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
 sb=st['#Strings'][0];bb=st['#Blob'][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

 traw,tname,tns,textends,tfl,tml=typedef(pe,rows,s,ix,z,o,sb,TYPE_RID)
 if (traw,tname,tns,textends)!=(TYPE_ROW,'PlayerController_Tutorial','',EXTENDS):raise E('Tutorial TypeDef')
 braw,bname,bns,bextends,bfl,bml=typedef(pe,rows,s,ix,z,o,sb,BASE_RID)
 if bname!='PlayerController' or bns!='':raise E('base TypeDef')

 raw,rva,impl,flags,name,sig,plist,owner,start,body=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Update',SIG,('PlayerController_Tutorial','')):raise E('method metadata')
 ho=base.off(ss,RVA)
 if pe[ho:ho+12].hex()!=HEADER:raise E('fat header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')

 for tok,(own,nm,row,sg) in FIELDS.items():
  if parent.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):raise E('field '+hex(tok))
 for tok,(nm,row,sg) in MEMBERS.items():
  if member(pe,rows,s,b,z,o,sb,bb,tok)!=(row,nm,sg):raise E('member '+hex(tok))

 amap=[]
 opbytes={'ldfld':0x7B,'ldflda':0x7C,'stfld':0x7D}
 for il,opname,tok in ACCESS:
  op=opbytes[opname]
  if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field access '+hex(il))
  amap.append({'il':f'0x{il:04X}','opcode':opname,'token':f'0x{tok:08X}'})
 d=hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=FIELD_ACCESS_DIGEST:raise E('field access digest '+d)

 if parent.internal_calls(body)!=EXPECTED_CALLS:raise E('internal calls '+repr(parent.internal_calls(body)))

 if body[0x0001]!=0x16 or body[0x0008]!=0x16:raise E('raw zero reset')
 if body[0x0019]!=0x39 or (0x001E+struct.unpack_from('<i',body,0x001A)[0])!=0x002F:raise E('Zone branch')
 if body[0x0024]!=0x1A:raise E('Start_ForceControl raw 4')
 for il in (0x0055,0x0089,0x00BD,0x00F1):
  if body[il]!=0x22 or body[il+1:il+5]!=bytes.fromhex('cdcccc3d'):raise E('0.1f threshold '+hex(il))
 for il,val in ((0x0067,4),(0x009B,8),(0x00CF,2),(0x0103,1)):
  if body[il] != {1:0x17,2:0x18,4:0x1A,8:0x1E}[val] or body[il+1]!=0x60:raise E('direction OR '+hex(il))
 if body[0x0120:0x0122]!=bytes([0x1F,30]) or body[0x014C:0x014E]!=bytes([0x1F,30]):raise E('rate raw 30')
 if body[0x012C:0x012F]!=bytes([0x02,0x1F,32]) or body[0x0134:0x0137]!=bytes([0x02,0x1F,32]):raise E('pinfall raw 32')
 if body[0x0158:0x015A]!=bytes([0x02,0x1E]):raise E('submission raw 8')

 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if rr!=[]:raise E('direct reference surface '+repr(rr))
 rdigest=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if rdigest!=REF_DIGEST:raise E('reference digest')
 cdigest=hashlib.sha256(b'').hexdigest()
 if cdigest!=CALLER_DIGEST:raise E('caller digest')

 base_update=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,BASE_UPDATE)
 if base_update[4]!='Update' or base_update[7]!=('PlayerController','') or base_update[3]!=0x01C6 or len(base_update[9])!=1 or hashlib.sha256(base_update[9]).hexdigest()!=BASE_UPDATE_SHA:raise E('base Update identity')
 ai=parent.mm(pe,ss,s,b,ix,z,o,sb,bb,owners,AI_UPDATE)
 if ai[1]!=AI_RVA or ai[4]!='Update' or ai[7]!=('PlayerController_AI','') or ai[3]!=0x00C6 or len(ai[9])!=984 or hashlib.sha256(ai[9]).hexdigest()!=AI_SHA:raise E('AI sibling identity')

 return {
  'code_size':352,
  'code_sha256':SHA,
  'canonical_internal_methoddef_reference_count':5,
  'direct_reference_count':0,
  'direct_caller_method_count':0,
  'remaining_override':'PlayerController_AI.Update'
 }

def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={
  'PlayerController_Tutorial.Update':0,
  'PlayerController_Tutorial.Process_Grapple':0,
  'Player.Start_ForceControl':0,
  'Player.End_ForceControl':0,
  'MatchMisc.mRate100Check':0,
  'PlayerController_AI.Update':0
 }
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
 a=argparse.ArgumentParser()
 a.add_argument('--dll',required=True)
 a.add_argument('--r6',required=True)
 x=a.parse_args()
 try:
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True))
  print('PROVE_PLAYERCONTROLLER_TUTORIAL_UPDATE: PASS')
  return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_TUTORIAL_UPDATE: FAIL')
  print(str(e))
  return 1

if __name__=='__main__':
 raise SystemExit(main())
