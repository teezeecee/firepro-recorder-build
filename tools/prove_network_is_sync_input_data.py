#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_external_update as ov
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6';DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d';EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004B48;RVA=0x002C1C50;ROW='501c2c0000008600070e0a00db490000ba37';SIG='200002';FLAGS=0x0086
LOCALS=0x11000FBA;LOCAL_BLOB='0708080812a78802080812a78808'
BODY=bytes.fromhex('027b915a00043902000000172a28654b0006390a00000028e70b000a3ab4000000160a3850000000060b027b9c5a0004072200002041a0027b9d5a000407179c06027b855a000440050000003823000000285d500006076f665000060c08282a00000a3a05000000380700000008186fac4e00060617580a06027b875a00043fa4ffffff7eec6400047bf26400047bcf6400043a190000007e4458000472f18d087020f00000006fc349000638140000007e44580004720f8e087020f00000006fc349000602177d915a000402177d905a0004162a027b8a5a00043a0900000002177d905a0004162a170d161304381f010000110413051104027b855a000440050000003803010000027b9d5a0004110591390500000038f0000000027b8a5a000411049a6f2c0e000a3acf000000160d027b9c5a000411058fce000001254e289902000a5856027b9c5a00041105982200002041439f000000027b9d5a00041105179c285d50000611056f6650000613061106282a00000a3a0500000038890000001106186fac4e00067eec6400047bf26400047bcf6400043a2c0000007e44580004724f8e0870027b945a000411049a725f8e0870281b00000a20f00000006fc349000638270000007e4458000472998e0870027b945a000411049a72bd8e0870281b00000a20f00000006fc349000602177d905a0004380e000000027b9c5a000411052200000000a01104175813041104027b875a00043fd4feffff027b905a00043a2f0000000939290000001613073814000000027b9c5a000411072200000000a01107175813071107027b875a00043fdfffffff092a');SHA='ac9ee661178e8c57fa83c0572a6bc65d650c99c1aff55185cc942f5e5c52c89d'
CHILDREN={
0x06004B65:('Network','Network_OnlineCheck','ac5bd6e06bc7d05f1d7ee9c98ceac6a1b2977018dbcf86cfe907dd7648953dad',[(0x000D,0x28)]),
0x0600505D:('PlayerMan','GetInst','592555acaf96cbd806fb44a0dfd643c83f27267edcf79fe7ab57ec6c0457b1ff',[(0x0051,0x28),(0x0164,0x28)]),
0x06005066:('PlayerMan','GetPlObjFromPadPort','9a4d894da22ead6979e399924710d5823a3a505447e40ef6b8c838c6e4b5123e',[(0x0057,0x6f),(0x016B,0x6f)]),
0x06004EAC:('Player','SetPlayerController','5dd13b1056dacf616fe2c9832bf85dbc4901c3911bfc2b75200c1f23b9301acb',[(0x006F,0x6f),(0x0186,0x6f)]),
0x060049C3:('DispNotification','Show','ce3eb15bbbe9c74bd34eb1405194a3556fbdfabec4a4c4cb4c53f72389a61a14',[(0x00A7,0x6f),(0x00C0,0x6f),(0x01C1,0x6f),(0x01ED,0x6f)])}
MEMBERS={
0x0A000BE7:('get_internetReachability','29060000710e070065db0000','0000118755',[(0x0017,0x28)]),
0x0A00002A:('op_Implicit','d100000085510600e9490000','0001021269',[(0x005E,0x28),(0x0174,0x28)]),
0x0A000E2C:('get_Count','dc130000f55206005e490000','200008',[(0x0125,0x6f)]),
0x0A000299:('get_deltaTime','510600003b6a0600a94d0000','00000c',[(0x0140,0x28)]),
0x0A00001B:('Concat','f9050000e15006008b490000','00030e0e0e0e',[(0x01B7,0x28),(0x01E3,0x28)])}
FIELDS={
0x04005A91:('Network','Match_Disconnect_Myself','060091ae030008000000','0602',[(0x0001,0x7b),(0x00C7,0x7d)]),
0x04005A9C:('Network','AsynchronousTime','01005eaf0300a7020000','061d0c',[(0x002B,0x7b),(0x0132,0x7b),(0x0148,0x7b),(0x01FF,0x7b),(0x0239,0x7b)]),
0x04005A9D:('Network','isAsynchronous_Timeout','01006faf030084090000','061d02',[(0x0038,0x7b),(0x010A,0x7b),(0x015B,0x7b)]),
0x04005A85:('Network','m_PlayerId','0100e7ad030001000000','0608',[(0x0042,0x7b),(0x00FA,0x7b)]),
0x04005A87:('Network','m_MaxPlayerNum','060004ae030001000000','0608',[(0x007A,0x7b),(0x0215,0x7b),(0x024F,0x7b)]),
0x040064EC:('SaveData','inst','160006220100413a0000','0612a938',[(0x0084,0x7e),(0x018B,0x7e)]),
0x040064F2:('SaveData','optionSettings','0600fe110400543a0000','0612a924',[(0x0089,0x7b),(0x0190,0x7b)]),
0x040064CF:('OptionSettings','language','06006bae010079080000','0611850c',[(0x008E,0x7b),(0x0195,0x7b)]),
0x04005844:('DispNotification','inst','160006220100ea320000','0612a440',[(0x0098,0x7e),(0x00B1,0x7e),(0x019F,0x7e),(0x01CB,0x7e)]),
0x04005A90:('Network','Match_Disconnect','060080ae030008000000','0602',[(0x00CE,0x7d),(0x00E2,0x7d),(0x01F4,0x7d),(0x0220,0x7b)]),
0x04005A8A:('Network','m_InputBuffer','010031ae0300ef330000','061d1512090111a5ac',[(0x00D6,0x7b),(0x011D,0x7b)]),
0x04005A94:('Network','UserName_List','0600ceae03006e020000','061d0e',[(0x01AA,0x7b),(0x01D6,0x7b)])}
REF_DIGEST='cfe844844eb440116d5e4c6af0a210c7cde294b4162cb9b60fc836c894837fba';CALLER_DIGEST='cc7198ef2ba8c683813e4a48d298e10ef5d7223a6d1d91459291249f87ffa5c3'
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1048576),b''):h.update(c)
 return h.hexdigest()
def mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
 rid=tok&0xffffff;p=o[6]+(rid-1)*z[6];raw=pe[p:p+z[6]];rva=struct.unpack_from('<I',raw)[0];impl=struct.unpack_from('<H',raw,4)[0];flags=struct.unpack_from('<H',raw,6)[0];q=p+8;ni,q=ov.base.rd(pe,q,s);si,q=ov.base.rd(pe,q,b);plist,q=ov.base.rd(pe,q,ix(8));start,body=ov.base.meth(pe,ss,rva) if rva else (None,b'')
 return raw.hex(),rva,impl,flags,ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body
def member(pe,rows,s,b,z,o,sb,bb,tok):
 rid=tok&0xffffff;psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2;p=o[10]+(rid-1)*z[10];raw=pe[p:p+z[10]];q=p+psz;ni,q=ov.base.rd(pe,q,s);si,_=ov.base.rd(pe,q,b)
 return raw.hex(),ov.base.s_at(pe,sb,ni),ov.base.blob(pe,bb,si).hex()
def all_refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
 needle=struct.pack('<I',T);out=[];pats=[(b'\x28'+needle,'call'),(b'\x6f'+needle,'callvirt'),(b'\x73'+needle,'newobj'),(b'\x27'+needle,'jmp'),(b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')]
 for rid in range(1,rows[6]+1):
  tok=0x06000000|rid;raw,rva,impl,flags,name,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if not body:continue
  for pat,opname in pats:
   pos=0
   while True:
    x=body.find(pat,pos)
    if x<0:break
    out.append({'caller_type':owner[0] if owner else None,'caller_namespace':owner[1] if owner else None,'caller_method':name,'caller_token':f'0x{tok:08X}','caller_rva':f'0x{rva:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname});pos=x+1
 out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']));return out
def verify_dll(path):
 pe=Path(path).read_bytes()
 if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL identity')
 ss,q=ov.base.secs(pe);st,hs,rows,tp=ov.base.mdstreams(pe,ss,q);s,b,ix,z,o=ov.base.tables(pe,st,hs,rows,tp);sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=ov.base.owner_maps(pe,rows,s,ix,z,o,sb)
 raw,rva,impl,flags,name,sig,plist,owner,start,body=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
 if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'IsSyncInputData',SIG,('Network','')):raise E('method metadata')
 ho=ov.base.off(ss,RVA);fs=struct.unpack_from('<H',pe,ho)[0]
 if fs!=0x3013 or struct.unpack_from('<H',pe,ho+2)[0]!=4 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCALS:raise E('fat header')
 lsrid=LOCALS&0xffffff;lsp=o[17]+(lsrid-1)*z[17];lsi,_=ov.base.rd(pe,lsp,b)
 if ov.base.blob(pe,bb,lsi).hex()!=LOCAL_BLOB:raise E('local signature')
 if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
 for tok,(own,nm,h,sites) in CHILDREN.items():
  cr,rv,im,fl,cn,cs,pl,co,cstart,cb=mm(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
  if co!=(own,'') or cn!=nm or hashlib.sha256(cb).hexdigest()!=h:raise E('child identity '+hex(tok))
  for il,op in sites:
   if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('child site '+hex(il))
 for tok,(nm,row,sg,sites) in MEMBERS.items():
  if member(pe,rows,s,b,z,o,sb,bb,tok)!=(row,nm,sg):raise E('member '+hex(tok))
  for il,op in sites:
   if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('member site '+hex(il))
 for tok,(own,nm,row,sg,sites) in FIELDS.items():
  rid=tok&0xffffff;p=o[4]+(rid-1)*z[4];q2=p+2;ni,q2=ov.base.rd(pe,q2,s);si,_=ov.base.rd(pe,q2,b)
  if pe[p:p+z[4]].hex()!=row or fm.get(rid)!=(own,'') or ov.base.s_at(pe,sb,ni)!=nm or ov.base.blob(pe,bb,si).hex()!=sg:raise E('field '+hex(tok))
  for il,op in sites:
   if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:raise E('field site '+hex(il))
 refs=all_refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
 if len(refs)!=3 or len({x['caller_token'] for x in refs})!=3:raise E('reference counts')
 if sum(x['opcode']=='call' for x in refs)!=2 or sum(x['opcode']=='callvirt' for x in refs)!=1:raise E('reference opcodes')
 d=hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if d!=REF_DIGEST:raise E('reference digest '+d)
 callers=sorted({x['caller_token'] for x in refs});cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
 if cd!=CALLER_DIGEST:raise E('caller digest '+cd)
 exp=[('0x06004B59','0x0001','call'),('0x06004B5B','0x0001','call'),('0x06005038','0x0005','callvirt')]
 if [(x['caller_token'],x['call_il'],x['opcode']) for x in refs]!=exp:raise E('caller map')
 return {'code_size':603,'code_sha256':SHA,'canonical_child_method_count':5,'direct_reference_count':3,'direct_caller_method_count':3,'reference_map_sha256':d}
def verify_r6(path):
 if sh(path)!=R6_SHA:raise E('R6 identity')
 wanted={'Network.IsSyncInputData':0,'Network.Is_Ready_KeyData':0,'Network.Clear_KeyBuffer':0,'PlayerController_Network.Update':0}
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
  print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True));print('PROVE_NETWORK_IS_SYNC_INPUT_DATA: PASS');return 0
 except Exception as e:
  print('PROVE_NETWORK_IS_SYNC_INPUT_DATA: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
