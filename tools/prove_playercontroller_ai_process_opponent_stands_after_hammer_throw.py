#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004FF2
RVA=0x002FB3C0
ROW='c0b32f0000008100f83b0a00db490000d93a'
SIG='200002'
FLAGS=0x0081
HEADER='13300300f80000001d110011'
BODY=bytes.fromhex('7efa610004027b4a6100047bb15f00046f655000060a7e556300047b7a6300040b027b4a6100047bb35f00047baa1000040c027b4a6100047bee5f00043902000000162a02167d5d610004067bbf5f0004289b4f00060d0918400d000000087b030d000413043808000000087b020d000413041104285b490006130520800100001306110545070000000500000005000000050000003b0000003b0000003b0000003b000000384b000000077b68640004194015000000027e8f610004110594110628ab4f00063810000000027e8e610004110594110628a84f00063815000000027e8f610004110594110628ab4f00063800000000172a')
SHA='f417f4eab0e62c6e31057c8c5123b17c930240b8a0691685c70a1fc40ca4e7d3'

LOCAL_SIG_TOKEN=0x1100111D
LOCAL_SIG_ROW='fdd00200'
LOCAL_SIG_BLOB='070712a78812a8f412863011a7c41d081185f008'
LOCAL_TYPES=[
 (2530,'Player','01001000fd480000000000005500565fa74e'),
 (2621,'VenueSetting','01001000447e000000000000090365645451'),
 (396,'AIParam','012010005b140000000000000903fa0c4110'),
 (2545,'DamageLevelEnum_LMH','030100005e7900000000000045039a612d50'),
 None,
 (380,'AIOpt_HammerThrough','01010000421300000000000045036c0c4010'),
 None
]

FIELDS={
 0x040061FA:('PlayerMan','inst','160006220100cf380000','0612a818'),
 0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
 0x04005FB1:('Player','TargetPlIdx','060071e0030001000000','0608'),
 0x04006355:('Ring','inst','16000622010036390000','0612a870'),
 0x0400637A:('Ring','venueSetting','06004208040065390000','0612a8f4'),
 0x04005FB3:('Player','WresParam','060088e003008f0b0000','061287ac'),
 0x040010AA:('WrestlerParam','aiParam','0600e95b0100810d0000','06128630'),
 0x04005FEE:('Player','Zone','0600dde203009f300000','0611a85c'),
 0x0400615D:('PlayerController_AI','isThrowOppopnentToRope','0600a0f3030008000000','0602'),
 0x04005FBF:('Player','HP','0600b67f010014000000','060c'),
 0x04000D03:('AIParam','throwToRope_HDmg','0600cc3a01008d030000','061d08'),
 0x04000D02:('AIParam','throwToRope_LDmg','0600bb3a01008d030000','061d08'),
 0x04006468:('VenueSetting','ringKind','0600630d0400cb390000','0611a8cc'),
 0x0400618F:('PlayerController_AI','prm_tbl_counter','110088f6030096380000','061d11a7d8'),
 0x0400618E:('PlayerController_AI','prm_tbl_run_atk','110078f6030090380000','061d11a7d0')
}
ACCESS=[
 (0x0000,'ldsfld',0x040061FA),(0x0006,'ldfld',0x0400614A),(0x000B,'ldfld',0x04005FB1),
 (0x0016,'ldsfld',0x04006355),(0x001B,'ldfld',0x0400637A),(0x0022,'ldfld',0x0400614A),
 (0x0027,'ldfld',0x04005FB3),(0x002C,'ldfld',0x040010AA),(0x0033,'ldfld',0x0400614A),
 (0x0038,'ldfld',0x04005FEE),(0x0046,'stfld',0x0400615D),(0x004C,'ldfld',0x04005FBF),
 (0x005F,'ldfld',0x04000D03),(0x006C,'ldfld',0x04000D02),(0x00AC,'ldfld',0x04006468),
 (0x00B8,'ldsfld',0x0400618F),(0x00CD,'ldsfld',0x0400618E),(0x00E2,'ldsfld',0x0400618F)
]
FIELD_DIGEST='09adedd34497a517e5eda5fa7692265274ca17b0572ee271a1575faf785712ff'

CALLS=[
 (0x0010,0x6F,0x06005065,'GetPlObj','PlayerMan',25,'32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8'),
 (0x0051,0x28,0x06004F9B,'GetDamageLevel_LMH','PlayerController_AI',49,'9c943eda48fd9f9c76271366324f22095426c06b0eecbb77d37e0cc945dde6c3'),
 (0x0075,0x28,0x0600495B,'LotOption','MatchMisc',52,'6d094b5b2ba805a275e1d97aa553088f42a9dbe4937cb83440b230ade378851f'),
 (0x00C2,0x28,0x06004FAB,'SetAIAct_Counter','PlayerController_AI',17,'d693e192b2928d1a36497d9296bc697e14ada6ab9d936c6cbc1134813b9d07e5'),
 (0x00D7,0x28,0x06004FA8,'SetAIAct_RunAttackAfterHammerThrow','PlayerController_AI',17,'2db5766f26c4ae6a892727404beaf78a217dfffc6413441ad9b174a58fcb2a7c'),
 (0x00EC,0x28,0x06004FAB,'SetAIAct_Counter','PlayerController_AI',17,'d693e192b2928d1a36497d9296bc697e14ada6ab9d936c6cbc1134813b9d07e5')
]
CALL_DIGEST='63dbe63042cbe01294261895504ac2c2593622772fe4249d987207d61bb09369'
BRANCHES=[
 {'il':'0x003D','opcode':'brfalse','target':'0x0044'},
 {'il':'0x0059','opcode':'bne.un','target':'0x006B'},
 {'il':'0x0066','opcode':'br','target':'0x0073'},
 {'il':'0x0085','opcode':'switch','targets':['0x00AB','0x00AB','0x00AB','0x00E1','0x00E1','0x00E1','0x00E1']},
 {'il':'0x00A6','opcode':'br','target':'0x00F6'},
 {'il':'0x00B2','opcode':'bne.un','target':'0x00CC'},
 {'il':'0x00C7','opcode':'br','target':'0x00DC'},
 {'il':'0x00DC','opcode':'br','target':'0x00F6'},
 {'il':'0x00F1','opcode':'br','target':'0x00F6'}
]
BRANCH_DIGEST='bac692035b37c351ce27308838ffedb016a31527eec272d826fa8810df323b2a'

EXPECTED_REFS=[
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'AIActFunc_CounterAttack','caller_token':'0x06004FC8','caller_rva':'0x002F8290','caller_code_size':480,'caller_code_sha256':'f1416a432df4293ddcbe42958f97f3e4f702ac0b2fa112b2a66636c7fa748a9f','call_il':'0x01C6','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple_Front','caller_token':'0x06004FE1','caller_rva':'0x002F9AB8','caller_code_size':407,'caller_code_sha256':'dd85a5c42843eb544814588585369b933af988f9a25a544093517603bde570ec','call_il':'0x0190','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple_BackAtk','caller_token':'0x06004FE3','caller_rva':'0x002F9D40','caller_code_size':334,'caller_code_sha256':'cd3deb24c9c49730460a7d595105d48c8d342600d53947160adc8feaffd546b0','call_il':'0x0147','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Update','caller_token':'0x0600502B','caller_rva':'0x002FFC68','caller_code_size':984,'caller_code_sha256':'6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9','call_il':'0x0276','opcode':'call'}
]
REF_DIGEST='a8838106a8579298d1c4c960f727ed2b0f572ad9f7cd3abd4c8fee500892d4e4'
CALLER_DIGEST='1a1b66420b281902d96e6d193ed31e681f7f9a2e1647fa0eadfa82f2574c40c6'

class E(RuntimeError): pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''): h.update(c)
    return h.hexdigest()

def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[(bytes([0x28])+needle,'call'),(bytes([0x6f])+needle,'callvirt'),
          (bytes([0x73])+needle,'newobj'),(bytes([0x27])+needle,'jmp'),
          (bytes([0xfe,0x06])+needle,'ldftn'),(bytes([0xfe,0x07])+needle,'ldvirtftn')]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        body=md[9]
        if not body: continue
        for pat,opname in pats:
            pos=0
            while True:
                x=body.find(pat,pos)
                if x<0: break
                out.append({
                    'caller_type':md[7][0] if md[7] else None,
                    'caller_namespace':md[7][1] if md[7] else None,
                    'caller_method':md[4],
                    'caller_token':f'0x{tok:08X}',
                    'caller_rva':f'0x{md[1]:08X}',
                    'caller_code_size':len(body),
                    'caller_code_sha256':hashlib.sha256(body).hexdigest(),
                    'call_il':f'0x{x:04X}','opcode':opname
                })
                pos=x+1
    out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
    return out

def target4(body,il):
    return il+5+struct.unpack_from('<i',body,il+1)[0]

def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=base.secs(pe)
    st,hs,rows,tp=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

    md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_OpponentStands_AfterHammerThrow',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    next_plist=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]
    if next_plist!=plist: raise E('unexpected parameters')

    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    if struct.unpack_from('<H',pe,ho+2)[0]!=3 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCAL_SIG_TOKEN:
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    sraw=pe[sp:sp+z[17]].hex()
    si,_=base.rd(pe,sp,b)
    if sraw!=LOCAL_SIG_ROW or base.blob(pe,bb,si).hex()!=LOCAL_SIG_BLOB:
        raise E('local signature')
    for item in LOCAL_TYPES:
        if item is None: continue
        rid,tname,rowhex=item
        traw,name,ns,_,_,_=drop.typedef(pe,rows,s,ix,z,o,sb,rid)
        if (traw,name,ns)!=(rowhex,tname,''): raise E('local type '+tname)

    for tok,(own,nm,row,sg) in FIELDS.items():
        if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):
            raise E('field '+hex(tok))

    opbytes={'ldfld':0x7b,'ldsfld':0x7e,'stfld':0x7d}
    amap=[]
    for il,opname,tok in ACCESS:
        if body[il]!=opbytes[opname] or struct.unpack_from('<I',body,il+1)[0]!=tok:
            raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opname,'token':f'0x{tok:08X}'})
    d=hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if d!=FIELD_DIGEST: raise E('field access digest '+d)

    got=drop.calls(body)
    expected=[(il,op,tok) for il,op,tok,_,_,_,_ in CALLS]
    if got!=expected: raise E('call surface '+repr(got))
    cmap=[]
    for il,op,tok,nm,own,size,h in CALLS:
        cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        if cm[4]!=nm or cm[7]!=(own,'') or len(cm[9])!=size or hashlib.sha256(cm[9]).hexdigest()!=h:
            raise E('child '+nm)
        cmap.append({'il':f'0x{il:04X}','opcode':'callvirt' if op==0x6f else 'call','token':f'0x{tok:08X}'})
    d=hashlib.sha256(json.dumps(cmap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if d!=CALL_DIGEST: raise E('call digest '+d)

    if body[0x003D]!=0x39 or target4(body,0x003D)!=0x0044: raise E('Zone branch')
    if body[0x0044:0x004B]!=bytes.fromhex('02167d5d610004'): raise E('raw false field write')
    if body[0x0058]!=0x18 or body[0x0059]!=0x40 or target4(body,0x0059)!=0x006B: raise E('raw damage split')
    if body[0x007C:0x0083]!=bytes.fromhex('20800100001306'): raise E('raw 384')
    if body[0x0085]!=0x45: raise E('switch opcode')
    n=struct.unpack_from('<I',body,0x0086)[0]
    base_il=0x008A+4*n
    sw=[base_il+struct.unpack_from('<i',body,0x008A+4*i)[0] for i in range(n)]
    if sw!=[0x00AB,0x00AB,0x00AB,0x00E1,0x00E1,0x00E1,0x00E1]: raise E('switch targets')
    if body[0x00B1]!=0x19 or body[0x00B2]!=0x40 or target4(body,0x00B2)!=0x00CC: raise E('ringKind raw3 split')
    if body[0x00F6:0x00F8]!=bytes.fromhex('172a'): raise E('true return')
    if body[0x0042:0x0044]!=bytes.fromhex('162a'): raise E('false return')

    bmap=BRANCHES
    d=hashlib.sha256(json.dumps(bmap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if d!=BRANCH_DIGEST: raise E('branch digest '+d)

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr},key=lambda x:int(x,16))
    cd=hashlib.sha256(''.join(x+'\n' for x in callers).encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {
      'code_size':248,'code_sha256':SHA,
      'field_access_count':18,'methoddef_call_site_count':6,'memberref_method_call_count':0,
      'branch_instruction_count':9,'direct_reference_count':4,'direct_caller_method_count':4,
      'reference_map_sha256':rd
    }

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'PlayerController_AI.Process_OpponentStands_AfterHammerThrow':0,
      'PlayerMan.GetPlObj':0,
      'PlayerController_AI.GetDamageLevel_LMH':0,
      'MatchMisc.LotOption':0,
      'PlayerController_AI.SetAIAct_Counter':0,
      'PlayerController_AI.SetAIAct_RunAttackAfterHammerThrow':0
    }
    with zipfile.ZipFile(path) as zf:
        if zf.testzip(): raise E('CRC')
        names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
        if len(names)!=1: raise E('event trace count')
        bts=zf.read(names[0])
        if hashlib.sha256(bts).hexdigest()!=EVENT_SHA: raise E('event trace identity')
        for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
            if row['method'] in wanted: wanted[row['method']]+=1
    if any(wanted.values()): raise E('R6 boundary '+repr(wanted))
    return dict(wanted,promoted_as_evidence=False)

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--dll',required=True)
    a.add_argument('--r6',required=True)
    x=a.parse_args()
    try:
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True))
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_OPPONENT_STANDS_AFTER_HAMMER_THROW: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_OPPONENT_STANDS_AFTER_HAMMER_THROW: FAIL')
        print(str(e))
        return 1

if __name__=='__main__': raise SystemExit(main())
