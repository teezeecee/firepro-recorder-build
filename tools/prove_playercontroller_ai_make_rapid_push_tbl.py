#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004FD4
RVA=0x002F8DC4
ROW='c48d2f000000860097390a005c480000c93a'
SIG='200001'
FLAGS=0x0086
HEADER='133004003401000007110011'
LOCAL_SIG_TOKEN=0x11001107
LOCAL_SIG_ROW='fbce0200'
LOCAL_SIG_BLOB='07090812a408128634080808080808'
BODY=bytes.fromhex('160a380d000000027b6361000406169c0617580a061f3c3febffffff7ed12a00047bd22a00040b7e380d0004077bd65700046f491000060c02087b330d0004087b340d00041758287b4900067d62610004027b62610004163d0800000002167d626100042a027b626100041f3c3e08000000021f3c7d626100041f3c027b626100045b0d1f3c027b626100045d13041613053810000000027b6f6100041105099e1105175813051105027b626100043fe3ffffff1613063818000000027b6f61000411068fd7000001254a175854110617581306110611043fdfffffff027b6f610004027b6261000428a74a0006161307161308382d0000001107027b6f61000411089458130711071f3c3e040000001f3c1307027b6361000411071759179c1108175813081108027b626100043fc6ffffff2a')
SHA='63b284583be3198f0647d16649fe43126b7f5c5d0b0c6a5c2ba73ad233530db7'

LOCAL_TYPES=[
 (2306,'MatchSetting','','01001000646c0000000000000903ce578749'),
 (397,'COMLevelData','','0100100063140000000000000903310d4410')
]
FIELDS={
 0x04006163:('PlayerController_AI','rapidPushTbl','010004f4030084090000','061d02'),
 0x04002AD1:('GlobalWork','inst','1600062201008d1a0000','061290c0'),
 0x04002AD2:('GlobalWork','MatchSetting','0600646c00007c1a0000','0612a408'),
 0x04000D38:('COMLevelDataManager','inst','1600062201007d0a0000','06128638'),
 0x040057D6:('MatchSetting','ComLevel','0600c54d000001000000','0608'),
 0x04000D33:('COMLevelData','pushButtonNumPerSecond_Min','0600da3d010001000000','0608'),
 0x04000D34:('COMLevelData','pushButtonNumPerSecond_Max','0600f53d010001000000','0608'),
 0x04006162:('PlayerController_AI','rapidPushRate','0100f6f3030001000000','0608'),
 0x0400616F:('PlayerController_AI','itv_tbl','0100c4f403008d030000','061d08')
}
ACCESS=[
 (0x0008,'ldfld',0x04006163),(0x001C,'ldsfld',0x04002AD1),(0x0021,'ldfld',0x04002AD2),
 (0x0027,'ldsfld',0x04000D38),(0x002D,'ldfld',0x040057D6),(0x003A,'ldfld',0x04000D33),
 (0x0040,'ldfld',0x04000D34),(0x004C,'stfld',0x04006162),(0x0052,'ldfld',0x04006162),
 (0x005F,'stfld',0x04006162),(0x0066,'ldfld',0x04006162),(0x0075,'stfld',0x04006162),
 (0x007D,'ldfld',0x04006162),(0x0087,'ldfld',0x04006162),(0x0098,'ldfld',0x0400616F),
 (0x00AA,'ldfld',0x04006162),(0x00BD,'ldfld',0x0400616F),(0x00DE,'ldfld',0x0400616F),
 (0x00E4,'ldfld',0x04006162),(0x00FC,'ldfld',0x0400616F),(0x0115,'ldfld',0x04006163),
 (0x0129,'ldfld',0x04006162)
]
FIELD_ACCESS_DIGEST='cdc1b72f1fe728d903a08a26adc43ef79cecfd76e804c2c4de31b0c48586404c'
CHILDREN=[
 (0x0032,0x6f,0x06001049,'COMLevelDataManager','GetCOMLevelData',9,'c78e8c870f4c865dfd55914f2c66fdca2c3d729088260483ece8ec917996123d'),
 (0x0047,0x28,0x0600497B,'MatchRandom','Range',30,'d6ed5dd5c1cdf595ca459ddc1c740ce66543e9630786cfdc9bf3404247f643f6'),
 (0x00E9,0x28,0x06004AA7,'Misc','Shuffle',65,'d8e87deae43facf68b16b094188ade6c7db1915caa3c59031cb85f891529b5c1')
]
CALL_DIGEST='bd2dc1ae5dc6ed8d33aa24d9c1c37f2bcc913c0bfb52a06fcda815c7f0eeb6df'
EXPECTED_REFS=[
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_PinfallDef','caller_token':'0x06005023','caller_rva':'0x002FF78C','caller_code_size':99,'caller_code_sha256':'8cd99966c2f677c3c5adb0b93e5ff520f7cccecc1d4c80f260694ad88c091a0a','call_il':'0x0030','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_SubmissionDef','caller_token':'0x06005024','caller_rva':'0x002FF7FC','caller_code_size':101,'caller_code_sha256':'a21e1f86232c9164c51d563bf7a8a425e873a25be4f142ccbdcb020c0bcc241e','call_il':'0x0030','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_ContestOfStrength','caller_token':'0x06005026','caller_rva':'0x002FF930','caller_code_size':74,'caller_code_sha256':'55f0bb53b03f366663707771d918a6cbe62aae003288dd23d7b1588c027de95b','call_il':'0x0020','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_ExchangeOfStriking','caller_token':'0x06005027','caller_rva':'0x002FF988','caller_code_size':75,'caller_code_sha256':'a9a368c56b9037b055142a1976b78a5dd686b761947964ed3a8809aa4f17e16d','call_il':'0x0020','opcode':'call'}
]
REF_DIGEST='2e789241bd7737ce018112b13a13f2ea82fe94b8f156d1d6e90dce4f16df7441'
CALLER_DIGEST='f93c47431bbc224c1fc332b07524951e4f1741e5a9de328ce0b58e8f2b8dbfb0'

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
        md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok); body=md[9]
        if not body: continue
        for pat,opname in pats:
            pos=0
            while True:
                x=body.find(pat,pos)
                if x<0: break
                out.append({'caller_type':md[7][0] if md[7] else None,'caller_namespace':md[7][1] if md[7] else None,
                            'caller_method':md[4],'caller_token':f'0x{tok:08X}','caller_rva':f'0x{md[1]:08X}',
                            'caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),
                            'call_il':f'0x{x:04X}','opcode':opname})
                pos=x+1
    out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
    return out

def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=base.secs(pe); st,hs,rows,tp=base.mdstreams(pe,ss,q); s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]; fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

    md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'MakeRapidPushTbl',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    if drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]!=plist: raise E('unexpected parameters')
    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    fs=struct.unpack_from('<H',pe,ho)[0]
    if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+4)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,4,308,LOCAL_SIG_TOKEN):
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    if pe[sp:sp+z[17]].hex()!=LOCAL_SIG_ROW: raise E('local signature row')
    si,_=base.rd(pe,sp,b)
    if base.blob(pe,bb,si).hex()!=LOCAL_SIG_BLOB: raise E('local signature blob')
    for rid,nm,ns,row in LOCAL_TYPES:
        if drop.typedef(pe,rows,s,ix,z,o,sb,rid)[:3]!=(row,nm,ns): raise E('local TypeDef '+nm)

    for tok,(own,nm,row,sg) in FIELDS.items():
        if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg): raise E('field '+hex(tok))
    opbytes={'ldfld':0x7b,'ldsfld':0x7e,'stfld':0x7d}
    amap=[]
    for il,opn,tok in ACCESS:
        if body[il]!=opbytes[opn] or struct.unpack_from('<I',body,il+1)[0]!=tok: raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opn,'token':f'0x{tok:08X}'})
    if hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_ACCESS_DIGEST:
        raise E('field access digest')

    if not (body[0x0000:0x0002]==bytes([0x16,0x0a]) and body[0x0002]==0x38 and drop.target4(body,0x0002)==0x0014):
        raise E('clear init')
    if not (body[0x000D:0x0010]==bytes([0x06,0x16,0x9c]) and body[0x0017]==0x3f and drop.target4(body,0x0017)==0x0007):
        raise E('clear loop')
    if not (body[0x0057]==0x16 and body[0x0058]==0x3d and drop.target4(body,0x0058)==0x0065):
        raise E('positive rate gate')
    if not (body[0x005D:0x0065]==bytes.fromhex('02167d626100042a')): raise E('zero return path')
    if not (body[0x006B:0x006D]==bytes([0x1f,60]) and body[0x006D]==0x3e and drop.target4(body,0x006D)==0x007A):
        raise E('60 clamp gate')
    if not (body[0x0072:0x007A]==bytes.fromhex('021f3c7d62610004')): raise E('60 clamp write')
    if not (body[0x007A:0x0084]==bytes.fromhex('1f3c027b626100045b0d')): raise E('division local3')
    if not (body[0x0084:0x008F]==bytes.fromhex('1f3c027b626100045d1304')): raise E('remainder local4')
    if not (body[0x0092]==0x38 and drop.target4(body,0x0092)==0x00A7 and body[0x00AF]==0x3f and drop.target4(body,0x00AF)==0x0097):
        raise E('interval fill loop')
    if not (body[0x00B7]==0x38 and drop.target4(body,0x00B7)==0x00D4 and body[0x00D8]==0x3f and drop.target4(body,0x00D8)==0x00BC):
        raise E('remainder distribute loop')
    if not (body[0x00C4]==0x8f and struct.unpack_from('<I',body,0x00C5)[0]==0x010000D7 and body[0x00C9:0x00CE]==bytes([0x25,0x4a,0x17,0x58,0x54])):
        raise E('Int32 in-place increment')
    if not (body[0x00F4]==0x38 and drop.target4(body,0x00F4)==0x0126 and body[0x012E]==0x3f and drop.target4(body,0x012E)==0x00F9):
        raise E('output loop')
    if not (body[0x0109:0x010B]==bytes([0x1f,60]) and body[0x010B]==0x3e and drop.target4(body,0x010B)==0x0114):
        raise E('output cap gate')
    if not (body[0x0110:0x0114]==bytes([0x1f,60,0x13,0x07])): raise E('output cap write')
    if not (body[0x011A:0x0120]==bytes([0x11,0x07,0x17,0x59,0x17,0x9c])): raise E('rapidPushTbl true write')

    got_calls=drop.calls(body)
    if got_calls!=[(x[0],x[1],x[2]) for x in CHILDREN]: raise E('call surface '+repr(got_calls))
    core=[]
    for il,op,tok,own,nm,size,h in CHILDREN:
        cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        if cm[4]!=nm or cm[7]!=(own,'') or len(cm[9])!=size or hashlib.sha256(cm[9]).hexdigest()!=h:
            raise E('child identity '+hex(tok))
        core.append({'il':f'0x{il:04X}','opcode':'callvirt' if op==0x6f else 'call','token':f'0x{tok:08X}'})
    if hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=CALL_DIGEST:
        raise E('call digest')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr})
    cd=hashlib.sha256((''.join(x+'\n' for x in callers)).encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {'code_size':308,'code_sha256':SHA,'canonical_internal_methoddef_reference_count':3,
            'external_memberref_method_call_count':0,'direct_reference_count':4,
            'direct_caller_method_count':4,'reference_map_sha256':rd}

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'PlayerController_AI.MakeRapidPushTbl':0,'COMLevelDataManager.GetCOMLevelData':0,
      'MatchRandom.Range':0,'Misc.Shuffle':0,'PlayerController_AI.Process_PinfallDef':0,
      'PlayerController_AI.Process_SubmissionDef':0,'PlayerController_AI.Process_ContestOfStrength':0,
      'PlayerController_AI.Process_ExchangeOfStriking':0
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
    a=argparse.ArgumentParser(); a.add_argument('--dll',required=True); a.add_argument('--r6',required=True); x=a.parse_args()
    try:
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True))
        print('PROVE_PLAYERCONTROLLER_AI_MAKE_RAPID_PUSH_TBL: PASS'); return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_MAKE_RAPID_PUSH_TBL: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
