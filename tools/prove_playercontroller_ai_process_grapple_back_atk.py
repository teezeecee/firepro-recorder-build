#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004FE3
RVA=0x002F9D40
ROW='409d2f0000008100a43a0a005c480000d43a'
SIG='200001'
FLAGS=0x0081
HEADER='133003004e01000011110011'
BODY=bytes.fromhex('027b4a6100047bb35f00047baa1000040a7efa610004027b4a6100047bb15f00046f655000060b027b606100041f273b41000000027b606100041f283b34000000027b606100041f293b27000000027b606100041f2a3b1a000000027b606100041f2b3b0d000000027b606100041f2c4025000000027b60610004286d1100060c02087be60e00047d1861000402087be60e00047d176100042a02157d60610004077bbf5f0004289b4f00060d0918400d000000067b010d000413043808000000067b000d000413041104285b4900061305027e456100041105947d18610004027e466100041105947d1761000411051c4057000000027b4a6100047bee5f00043a40000000027b4a6100047caa5f00047b0a00000a225455d53e4126000000027b4a6100047caa5f00047b0a00000a225455d5be430c000000021a7d1761000438070000000228f24f0006262a')
SHA='cd3deb24c9c49730460a7d595105d48c8d342600d53947160adc8feaffd546b0'

LOCAL_SIG_TOKEN=0x11001111
LOCAL_SIG_ROW='d0cf0200'
LOCAL_SIG_BLOB='070612863012a78812870411a7c41d081185ec'
LOCAL_TYPES=[
 (396,'AIParam','012010005b140000000000000903fa0c4110'),
 (2530,'Player','01001000fd480000000000005500565fa74e'),
 (449,'SkillSlotData','0100100098170000000000000903e10e6b11'),
 (2545,'DamageLevelEnum_LMH','030100005e7900000000000045039a612d50'),
 None,
 (379,'AIOpt_BackGrapple','0101000030130000000000004503630c4010')
]

FIELDS={
 0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
 0x04005FB3:('Player','WresParam','060088e003008f0b0000','061287ac'),
 0x040010AA:('WrestlerParam','aiParam','0600e95b0100810d0000','06128630'),
 0x040061FA:('PlayerMan','inst','160006220100cf380000','0612a818'),
 0x04005FB1:('Player','TargetPlIdx','060071e0030001000000','0608'),
 0x04006160:('PlayerController_AI','nextSkill','0100daf30300720a0000','0611870c'),
 0x04000EE6:('SkillSlotData','attackButton','0600384d0100440c0000','0611904c'),
 0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c'),
 0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c'),
 0x04005FBF:('Player','HP','0600b67f010014000000','060c'),
 0x04000D01:('AIParam','holdBack_HDmg','0600ad3a01008d030000','061d08'),
 0x04000D00:('AIParam','holdBack_LDmg','06009f3a01008d030000','061d08'),
 0x04006145:('PlayerController_AI','_BackButTbl','11005df20300e0190000','061d11904c'),
 0x04006146:('PlayerController_AI','_BackKeyTbl','110069f20300e0190000','061d11904c'),
 0x04005FEE:('Player','Zone','0600dde203009f300000','0611a85c'),
 0x04005FAA:('Player','PlPos','060039e0030070000000','061119')
}
ACCESS=[
 (0x0001,'ldfld',0x0400614A),(0x0006,'ldfld',0x04005FB3),(0x000B,'ldfld',0x040010AA),
 (0x0011,'ldsfld',0x040061FA),(0x0017,'ldfld',0x0400614A),(0x001C,'ldfld',0x04005FB1),
 (0x0028,'ldfld',0x04006160),(0x0035,'ldfld',0x04006160),(0x0042,'ldfld',0x04006160),
 (0x004F,'ldfld',0x04006160),(0x005C,'ldfld',0x04006160),(0x0069,'ldfld',0x04006160),
 (0x0076,'ldfld',0x04006160),(0x0083,'ldfld',0x04000EE6),(0x0088,'stfld',0x04006118),
 (0x008F,'ldfld',0x04000EE6),(0x0094,'stfld',0x04006117),(0x009C,'stfld',0x04006160),
 (0x00A2,'ldfld',0x04005FBF),(0x00B5,'ldfld',0x04000D01),(0x00C2,'ldfld',0x04000D00),
 (0x00D3,'ldsfld',0x04006145),(0x00DB,'stfld',0x04006118),(0x00E1,'ldsfld',0x04006146),
 (0x00E9,'stfld',0x04006117),(0x00F7,'ldfld',0x0400614A),(0x00FC,'ldfld',0x04005FEE),
 (0x0107,'ldfld',0x0400614A),(0x010C,'ldflda',0x04005FAA),(0x0111,'ldfld',0x0A00000A),
 (0x0121,'ldfld',0x0400614A),(0x0126,'ldflda',0x04005FAA),(0x012B,'ldfld',0x0A00000A),
 (0x013C,'stfld',0x04006117)
]
FIELD_DIGEST='3b92933eebc8580ee0cffd0630322850d175e377c3ed1a9cbb24a81b4f81081b'
Y_MEMBER=0x0A00000A
Y_ROW='31000000e1b6000014000000'
Y_SIG='060c'
Y_PARENT_RAW=49
VECTOR3_TYPEREF_RID=6
VECTOR3_ROW='0600f4a9000080a60000'

CALLS=[
 (0x0021,0x6F,0x06005065,'GetPlObj','PlayerMan',25,'32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8'),
 (0x007B,0x28,0x0600116D,'GetSkillSlotData','SkillSlotDataMan',25,'fd2a546fcbc44dcd97c1376e5f5ba1802555f5b7f8c21d8ab3c123b3cf7fc0f0'),
 (0x00A7,0x28,0x06004F9B,'GetDamageLevel_LMH','PlayerController_AI',49,'9c943eda48fd9f9c76271366324f22095426c06b0eecbb77d37e0cc945dde6c3'),
 (0x00CB,0x28,0x0600495B,'LotOption','MatchMisc',52,'6d094b5b2ba805a275e1d97aa553088f42a9dbe4937cb83440b230ade378851f'),
 (0x0147,0x28,0x06004FF2,'Process_OpponentStands_AfterHammerThrow','PlayerController_AI',248,'f417f4eab0e62c6e31057c8c5123b17c930240b8a0691685c70a1fc40ca4e7d3')
]
CALL_DIGEST='0b99eec8230541d7e5307c71eab3b3b16e1a01134f19757a283843813f02798b'
BRANCHES=[
 ('0x002F','beq','0x0075'),('0x003C','beq','0x0075'),('0x0049','beq','0x0075'),
 ('0x0056','beq','0x0075'),('0x0063','beq','0x0075'),('0x0070','bne.un','0x009A'),
 ('0x00AF','bne.un','0x00C1'),('0x00BC','br','0x00C9'),('0x00F1','bne.un','0x014D'),
 ('0x0101','brtrue','0x0146'),('0x011B','bge.un','0x0146'),('0x0135','ble.un','0x0146'),
 ('0x0141','br','0x014D')
]
BRANCH_DIGEST='5d817c66627c6512920a24cde32fb45f88ed13d93135db64ae4695b2c7770abe'

EXPECTED_REFS=[{
 'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple',
 'caller_token':'0x06004FE4','caller_rva':'0x002F9E9C','caller_code_size':709,
 'caller_code_sha256':'221fc977746121dd811fe1d13e59502c160992648d03561b81e6b7555e04ea42',
 'call_il':'0x0193','opcode':'call'
}]
REF_DIGEST='de2e286c63882ce40f5d0baa1e135f274e7d2090f0832b30e01c5042281a6d79'
CALLER_DIGEST='d02a9d70f80b20a5296e5cd052dbe75e74bbd8fde7609e8a8f76768a9b75f199'

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
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_Grapple_BackAtk',SIG,('PlayerController_AI','')):
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

    yraw,yparent,yname,ysig=drop.member(pe,rows,s,b,z,o,sb,bb,Y_MEMBER)
    if (yraw,yparent,yname,ysig)!=(Y_ROW,Y_PARENT_RAW,'y',Y_SIG):
        raise E('Vector3.y MemberRef')
    traw,scope,tname,tns=drop.typeref(pe,s,z,o,sb,VECTOR3_TYPEREF_RID)
    if (traw,tname,tns)!=(VECTOR3_ROW,'Vector3','UnityEngine'):
        raise E('Vector3 TypeRef')

    opbytes={'ldfld':0x7b,'ldflda':0x7c,'stfld':0x7d,'ldsfld':0x7e}
    amap=[]
    for il,opname,tok in ACCESS:
        if body[il]!=opbytes[opname] or struct.unpack_from('<I',body,il+1)[0]!=tok:
            raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opname,'token':f'0x{tok:08X}'})
    d=hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if d!=FIELD_DIGEST: raise E('field digest '+d)

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

    for il,v in [(0x002D,39),(0x003A,40),(0x0047,41),(0x0054,42),(0x0061,43),(0x006E,44)]:
        if body[il:il+2]!=bytes([0x1f,v]): raise E('nextSkill raw '+str(v))
    if body[0x009A:0x00A1]!=bytes.fromhex('02157d60610004'): raise E('nextSkill -1 write')
    if body[0x00AE]!=0x18: raise E('damage raw2')
    if body[0x00F0]!=0x1c: raise E('LotOption raw6')
    if body[0x0116]!=0x22 or body[0x0117:0x011B]!=bytes.fromhex('5455d53e'): raise E('positive y boundary')
    if body[0x0130]!=0x22 or body[0x0131:0x0135]!=bytes.fromhex('5455d5be'): raise E('negative y boundary')
    if body[0x013A:0x0141]!=bytes.fromhex('021a7d17610004'): raise E('padOn raw4')
    if body[0x0147]!=0x28 or struct.unpack_from('<I',body,0x0148)[0]!=0x06004FF2 or body[0x014C]!=0x26 or body[0x014D]!=0x2a:
        raise E('FACT-0246 call/pop/ret')

    branch_ops={'beq':0x3b,'bne.un':0x40,'br':0x38,'brtrue':0x3a,'bge.un':0x41,'ble.un':0x43}
    bmap=[]
    for ils,opname,targets in BRANCHES:
        il=int(ils,16); target=int(targets,16)
        if body[il]!=branch_ops[opname] or target4(body,il)!=target:
            raise E('branch '+ils)
        bmap.append({'il':ils,'opcode':opname,'target':targets})
    d=hashlib.sha256(json.dumps(bmap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if d!=BRANCH_DIGEST: raise E('branch digest '+d)

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    cd=hashlib.sha256(('0x06004FE4\n').encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {
      'code_size':334,'code_sha256':SHA,'field_access_count':34,
      'methoddef_call_site_count':5,'memberref_method_call_count':0,
      'branch_instruction_count':13,'direct_reference_count':1,'direct_caller_method_count':1,
      'reference_map_sha256':rd
    }

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'PlayerController_AI.Process_Grapple_BackAtk':0,
      'PlayerMan.GetPlObj':0,
      'SkillSlotDataMan.GetSkillSlotData':0,
      'PlayerController_AI.GetDamageLevel_LMH':0,
      'MatchMisc.LotOption':0,
      'PlayerController_AI.Process_OpponentStands_AfterHammerThrow':0,
      'PlayerController_AI.Process_Grapple':0
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
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_GRAPPLE_BACK_ATK: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_GRAPPLE_BACK_ATK: FAIL')
        print(str(e))
        return 1

if __name__=='__main__': raise SystemExit(main())
