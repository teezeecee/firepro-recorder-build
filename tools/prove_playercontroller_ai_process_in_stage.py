#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06005013; RVA=0x002FDEE8; ROW='e8de2f0000008100863e0a00db490000de3a'; SIG='200002'; FLAGS=0x0081
HEADER='13300200040100008e020011'
BODY=bytes.fromhex('027b4a6100047bee5f00041f093b02000000162a027b4a6100047bb75f00041f164002000000162a02167d5d610004027b4a6100047b49600004390d000000021f207d1761000438b6000000027b4a6100047b77600004396c0000007efa610004027b4a6100047bb15f00046f655000060a067bee5f00041f093b47000000067bee5f00041f0a3b3a000000027b4a6100047caa5f00047b0a00000a027b4a6100047caa5f00047b0900000a430c00000002187d176100043807000000021a7d17610004172a162a027b4a6100047caa5f00047b0a00000a027b4a6100047caa5f00047b0900000a430c00000002187d176100043807000000021a7d17610004172a162a')
SHA='689a04f4f28bef50f618fd9599e843cc189efae42457ebde181d5429c34bbc5d'
LOCAL_SIG_TOKEN=0x1100028E; LOCAL_SIG_ROW='6b940100'; LOCAL_SIG_BLOB='070112a788'
PLAYER_TYPE_RID=2530; PLAYER_TYPE_ROW='01001000fd480000000000005500565fa74e'
FIELDS={
0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
0x04005FEE:('Player','Zone','0600dde203009f300000','0611a85c'),
0x04005FB7:('Player','State','06006e000000da370000','0611a828'),
0x0400615D:('PlayerController_AI','isThrowOppopnentToRope','0600a0f3030008000000','0602'),
0x04006049:('Player','isPinfallDef','060071e7030008000000','0602'),
0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c'),
0x04006077:('Player','isIntruder','0600b48c030008000000','0602'),
0x040061FA:('PlayerMan','inst','160006220100cf380000','0612a818'),
0x04005FB1:('Player','TargetPlIdx','060071e0030001000000','0608'),
0x04005FAA:('Player','PlPos','060039e0030070000000','061119')}
MEMBERS={
0x0A000009:('x','31000000dfb6000014000000','060c'),
0x0A00000A:('y','31000000e1b6000014000000','060c')}
ACCESS=[
(0x0001,'ldfld',0x0400614A),(0x0006,'ldfld',0x04005FEE),(0x0015,'ldfld',0x0400614A),(0x001A,'ldfld',0x04005FB7),
(0x002A,'stfld',0x0400615D),(0x0030,'ldfld',0x0400614A),(0x0035,'ldfld',0x04006049),(0x0042,'stfld',0x04006117),
(0x004D,'ldfld',0x0400614A),(0x0052,'ldfld',0x04006077),(0x005C,'ldsfld',0x040061FA),(0x0062,'ldfld',0x0400614A),
(0x0067,'ldfld',0x04005FB1),(0x0073,'ldfld',0x04005FEE),(0x0080,'ldfld',0x04005FEE),(0x008D,'ldfld',0x0400614A),
(0x0092,'ldflda',0x04005FAA),(0x0097,'ldfld',0x0A00000A),(0x009D,'ldfld',0x0400614A),(0x00A2,'ldflda',0x04005FAA),
(0x00A7,'ldfld',0x0A000009),(0x00B3,'stfld',0x04006117),(0x00BF,'stfld',0x04006117),(0x00C9,'ldfld',0x0400614A),
(0x00CE,'ldflda',0x04005FAA),(0x00D3,'ldfld',0x0A00000A),(0x00D9,'ldfld',0x0400614A),(0x00DE,'ldflda',0x04005FAA),
(0x00E3,'ldfld',0x0A000009),(0x00EF,'stfld',0x04006117),(0x00FB,'stfld',0x04006117)]
FIELD_ACCESS_DIGEST='24c3e38f3901443214d521c6eebcc6eaab6a535d3154f5d6e2c70a98b333bbe2'
CHILD=0x06005065; CHILD_SHA='32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8'
PARENT=0x0600502B; PARENT_RVA=0x002FFC68; PARENT_SIZE=984; PARENT_SHA='6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9'; PARENT_CALL_IL=0x0316
REF_DIGEST='c7c0815170574360afc45486afe6ceb91f06badddb65f76a85f5642b16651c90'; CALLER_DIGEST='8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63'
class E(RuntimeError): pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def cu(blob,pos):
 x=blob[pos]
 if x<0x80:return x,pos+1
 if x<0xC0:return ((x&0x3f)<<8)|blob[pos+1],pos+2
 return ((x&0x1f)<<24)|(blob[pos+1]<<16)|(blob[pos+2]<<8)|blob[pos+3],pos+4
def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
 needle=struct.pack('<I',T);pats=[(bytes([0x28])+needle,'call'),(bytes([0x6f])+needle,'callvirt'),(bytes([0x73])+needle,'newobj'),(bytes([0x27])+needle,'jmp'),(bytes([0xfe,0x06])+needle,'ldftn'),(bytes([0xfe,0x07])+needle,'ldvirtftn')];out=[]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid;md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok);body=md[9]
  if not body:continue
  for pat,opname in pats:
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':md[7][0] if md[7] else None,'caller_namespace':md[7][1] if md[7] else None,'caller_method':md[4],'caller_token':f'0x{tok:08X}','caller_rva':f'0x{md[1]:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']));return out
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T);raw,rva,impl,flags,name,sig,plist,owner,start,body=md
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_InStage',SIG,('PlayerController_AI','')):raise E('method metadata')
 ho=base.off(ss,RVA)
 if pe[ho:ho+12].hex()!=HEADER or struct.unpack_from('<H',pe,ho+2)[0]!=2 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCAL_SIG_TOKEN:raise E('header')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17];sraw=pe[sp:sp+z[17]].hex();si,_=base.rd(pe,sp,b);lblob=base.blob(pe,bb,si)
 if sraw!=LOCAL_SIG_ROW or lblob.hex()!=LOCAL_SIG_BLOB:raise E('local signature')
 coded,end=cu(lblob,3)
 if lblob[:3]!=bytes([0x07,0x01,0x12]) or (coded&3)!=0 or (coded>>2)!=PLAYER_TYPE_RID or end!=len(lblob):raise E('local type')
 if drop.typedef(pe,rows,s,ix,z,o,sb,PLAYER_TYPE_RID)[:3]!=(PLAYER_TYPE_ROW,'Player',''):raise E('Player TypeDef')
 for tok,(own,nm,row,sg) in FIELDS.items():
  if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):raise E('field '+hex(tok))
 for tok,(nm,row,sg) in MEMBERS.items():
  mr=drop.member(pe,rows,s,b,z,o,sb,bb,tok)
  if (mr[0],mr[2],mr[3])!=(row,nm,sg):raise E('member '+hex(tok))
 amap=[];opbytes={'ldfld':0x7b,'ldflda':0x7c,'ldsfld':0x7e,'stfld':0x7d}
 for il,opn,tok in ACCESS:
  if body[il]!=opbytes[opn] or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field access '+hex(il))
  amap.append({'il':f'0x{il:04X}','opcode':opn,'token':f'0x{tok:08X}'})
 if hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_ACCESS_DIGEST:raise E('field digest')
 if drop.calls(body)!=[(0x006C,0x6f,CHILD)]:raise E('call surface '+repr(drop.calls(body)))
 cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
 if cm[4]!='GetPlObj' or cm[7]!=('PlayerMan','') or len(cm[9])!=25 or hashlib.sha256(cm[9]).hexdigest()!=CHILD_SHA:raise E('FACT-0109 identity')
 for il,op,target in [(0x000D,0x3b,0x0014),(0x0021,0x40,0x0028),(0x003A,0x39,0x004C),(0x0047,0x38,0x0102),(0x0057,0x39,0x00C8),(0x007A,0x3b,0x00C6),(0x0087,0x3b,0x00C6),(0x00AC,0x43,0x00BD),(0x00B8,0x38,0x00C4),(0x00E8,0x43,0x00F9),(0x00F4,0x38,0x0100)]:
  if body[il]!=op or drop.target4(body,il)!=target:raise E('branch '+hex(il))
 if not (body[0x0B:0x0D]==bytes([0x1f,9]) and body[0x0D]==0x3b and body[0x12]==0x16 and body[0x13]==0x2a):raise E('Zone 9 entry orientation')
 if not (body[0x1F:0x21]==bytes([0x1f,22]) and body[0x21]==0x40 and drop.target4(body,0x21)==0x28 and body[0x26]==0x16 and body[0x27]==0x2a):raise E('State 22 false-return orientation')
 if not (body[0x29]==0x16 and body[0x2A]==0x7d):raise E('flag clear')
 if not (body[0x40:0x42]==bytes([0x1f,32]) and body[0x42]==0x7d):raise E('padOn 32')
 if not (body[0x78:0x7A]==bytes([0x1f,9]) and body[0x85:0x87]==bytes([0x1f,10])):raise E('target Zone literals')
 if not (body[0x97]==0x7b and struct.unpack_from('<I',body,0x98)[0]==0x0A00000A and body[0xA7]==0x7b and struct.unpack_from('<I',body,0xA8)[0]==0x0A000009 and body[0xAC]==0x43):raise E('intruder PlPos ble.un order')
 if not (body[0xD3]==0x7b and struct.unpack_from('<I',body,0xD4)[0]==0x0A00000A and body[0xE3]==0x7b and struct.unpack_from('<I',body,0xE4)[0]==0x0A000009 and body[0xE8]==0x43):raise E('non-intruder PlPos ble.un order')
 for il,val in ((0xB2,2),(0xBE,4),(0xEE,2),(0xFA,4)):
  if body[il]!={2:0x18,4:0x1a}[val] or body[il+1]!=0x7d:raise E('pad write '+hex(il))
 rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 expected=[{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Update','caller_token':'0x0600502B','caller_rva':'0x002FFC68','caller_code_size':984,'caller_code_sha256':PARENT_SHA,'call_il':'0x0316','opcode':'call'}]
 if rr!=expected:raise E('reference surface '+repr(rr))
 rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if rd!=REF_DIGEST or hashlib.sha256(('0x0600502B\n').encode()).hexdigest()!=CALLER_DIGEST:raise E('reference digest')
 pm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,PARENT)
 if pm[1]!=PARENT_RVA or pm[4]!='Update' or pm[7]!=('PlayerController_AI','') or len(pm[9])!=PARENT_SIZE or hashlib.sha256(pm[9]).hexdigest()!=PARENT_SHA or pm[9][PARENT_CALL_IL]!=0x28 or struct.unpack_from('<I',pm[9],PARENT_CALL_IL+1)[0]!=T:raise E('parent')
 return {'code_size':260,'code_sha256':SHA,'canonical_internal_methoddef_reference_count':1,'external_memberref_method_call_count':0,'direct_reference_count':1,'direct_caller_method_count':1,'reference_map_sha256':rd}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'PlayerController_AI.Process_InStage':0,'PlayerMan.GetPlObj':0,'PlayerController_AI.Update':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_PLAYERCONTROLLER_AI_PROCESS_IN_STAGE: PASS');return 0
 except Exception as e:
  print('PROVE_PLAYERCONTROLLER_AI_PROCESS_IN_STAGE: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
