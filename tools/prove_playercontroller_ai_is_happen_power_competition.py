#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004FD3
RVA=0x002F8D90
ROW='908d2f00000096007e390a00634a0000c93a'
SIG='000002'
FLAGS=0x0096
HEADER='133002002800000006110011'
LOCAL_SIG_TOKEN=0x11001106
LOCAL_SIG_ROW='f2ce0200'
LOCAL_SIG_BLOB='070212a408128634'
BODY=bytes.fromhex('7ed12a00047bd22a00040a7e380d0004067bd65700046f491000060b077b350d000428554900062a')
SHA='6d6d6ede32b0294d70267f18c929adf5a196a0ca8f720d77547385aa1df8c414'

LOCAL_TYPES=[
 (2306,'MatchSetting','','01001000646c0000000000000903ce578749'),
 (397,'COMLevelData','','0100100063140000000000000903310d4410')
]
FIELDS={
 0x04002AD1:('GlobalWork','inst','1600062201008d1a0000','061290c0'),
 0x04002AD2:('GlobalWork','MatchSetting','0600646c00007c1a0000','0612a408'),
 0x04000D38:('COMLevelDataManager','inst','1600062201007d0a0000','06128638'),
 0x040057D6:('MatchSetting','ComLevel','0600c54d000001000000','0608'),
 0x04000D35:('COMLevelData','powerCompetitionProbability','0600103e010001000000','0608')
}
ACCESS=[
 (0x0000,'ldsfld',0x04002AD1),(0x0005,'ldfld',0x04002AD2),
 (0x000B,'ldsfld',0x04000D38),(0x0011,'ldfld',0x040057D6),
 (0x001D,'ldfld',0x04000D35)
]
FIELD_ACCESS_DIGEST='0d82e900d994aa16f6dcba6c1997d958f532f93942c1c3a2a2517363747a57ea'
CHILDREN=[
 (0x0016,0x6f,0x06001049,'COMLevelDataManager','GetCOMLevelData',9,'c78e8c870f4c865dfd55914f2c66fdca2c3d729088260483ece8ec917996123d'),
 (0x0022,0x28,0x06004955,'MatchMisc','mRate100Check',38,'6899b69e72e4f0b5853a85c1cb3796e28442d2abbd4ca2378d72dd59ce7bba58')
]
CALL_DIGEST='17c876cb0d2798f3c6cf17a2b3a7c251f68043c89721221f0424eb92fddf495f'
EXPECTED_REFS=[{
 'caller_type':'Player','caller_namespace':'','caller_method':'CheckStartPowerCompetition',
 'caller_token':'0x06004EF4','caller_rva':'0x002E3320','caller_code_size':309,
 'caller_code_sha256':'014d272b72f5c823d163e2f95b9346fd02b807cd12c664c21bb5ca70f702c486',
 'call_il':'0x0091','opcode':'call'
}]
REF_DIGEST='c82055581e56aa04315cd68fcbcd0be36b84b86173219a87aab1cc8c2674ad9f'
CALLER_DIGEST='544c8e0063de5501ba82bd3fffb3548fdcf570f7061c0b4ed01a33a29e84bca9'

class E(RuntimeError): pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''): h.update(c)
    return h.hexdigest()

def cu(blob,pos):
    x=blob[pos]
    if x<0x80: return x,pos+1
    if x<0xC0: return ((x&0x3f)<<8)|blob[pos+1],pos+2
    return ((x&0x1f)<<24)|(blob[pos+1]<<16)|(blob[pos+2]<<8)|blob[pos+3],pos+4

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
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'IsHappenPowerCompetition',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    if drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]!=plist: raise E('unexpected parameters')
    if bytes.fromhex(sig)!=bytes([0x00,0x00,0x02]): raise E('signature')

    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    fs=struct.unpack_from('<H',pe,ho)[0]
    if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+4)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,2,40,LOCAL_SIG_TOKEN):
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    if pe[sp:sp+z[17]].hex()!=LOCAL_SIG_ROW: raise E('local signature row')
    si,_=base.rd(pe,sp,b); lblob=base.blob(pe,bb,si)
    if lblob.hex()!=LOCAL_SIG_BLOB or lblob[:2]!=bytes([0x07,0x02]): raise E('local signature blob')
    pos=2
    for rid,nm,ns,row in LOCAL_TYPES:
        if lblob[pos]!=0x12: raise E('local class marker')
        coded,pos=cu(lblob,pos+1)
        if (coded&3)!=0 or (coded>>2)!=rid: raise E('local TypeDef coding')
        if drop.typedef(pe,rows,s,ix,z,o,sb,rid)[:3]!=(row,nm,ns): raise E('local TypeDef metadata')
    if pos!=len(lblob): raise E('local signature tail')

    for tok,(own,nm,row,sg) in FIELDS.items():
        if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg): raise E('field '+hex(tok))
    amap=[]; opbytes={'ldfld':0x7b,'ldsfld':0x7e}
    for il,opn,tok in ACCESS:
        if body[il]!=opbytes[opn] or struct.unpack_from('<I',body,il+1)[0]!=tok: raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opn,'token':f'0x{tok:08X}'})
    if hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_ACCESS_DIGEST:
        raise E('field access digest')

    actual_calls=drop.calls(body)
    if actual_calls!=[(x[0],x[1],x[2]) for x in CHILDREN]: raise E('call surface '+repr(actual_calls))
    call_core=[]
    for il,op,tok,own,nm,size,h in CHILDREN:
        cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        if cm[4]!=nm or cm[7]!=(own,'') or len(cm[9])!=size or hashlib.sha256(cm[9]).hexdigest()!=h:
            raise E('child identity '+hex(tok))
        call_core.append({'il':f'0x{il:04X}','opcode':'callvirt' if op==0x6f else 'call','token':f'0x{tok:08X}'})
    if hashlib.sha256(json.dumps(call_core,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=CALL_DIGEST:
        raise E('call digest')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr})
    cd=hashlib.sha256((''.join(x+'\n' for x in callers)).encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {'code_size':40,'code_sha256':SHA,'canonical_internal_methoddef_reference_count':2,
            'external_memberref_method_call_count':0,'direct_reference_count':1,
            'direct_caller_method_count':1,'reference_map_sha256':rd}

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'PlayerController_AI.IsHappenPowerCompetition':0,
      'Player.CheckStartPowerCompetition':0,
      'COMLevelDataManager.GetCOMLevelData':0,
      'MatchMisc.mRate100Check':0
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
        print('PROVE_PLAYERCONTROLLER_AI_IS_HAPPEN_POWER_COMPETITION: PASS'); return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_IS_HAPPEN_POWER_COMPETITION: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
