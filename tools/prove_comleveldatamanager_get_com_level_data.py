#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06001049
RVA=0x00061357
ROW='57130600000086003f780800699701001d0c'
SIG='200112863408'
FLAGS=0x0086
TINY_HEADER='26'
BODY=bytes.fromhex('027b390d0004039a2a')
SHA='c78e8c870f4c865dfd55914f2c66fdca2c3d729088260483ece8ec917996123d'

PARAM_RID=3101
PARAM_ROW='00000100e9850100'
RETURN_TYPE_RID=397
RETURN_TYPE_ROW='0100100063140000000000000903310d4410'
FIELD=0x04000D39
FIELD_ROW='0100483e0100820a0000'
FIELD_SIG='061d128634'
FIELD_ACCESS_DIGEST='9224c351b8ac43b7cbe994bfa4df3363ca01e644911b62a0127ef74798e35d4c'

REF_DIGEST='13d6ab1931848d868c91a13dfdf800e3a6d27355281f8a74741e51aef1a70c79'
CALLER_DIGEST='ffa09db9952975b9f41544ea8e0e0ad4319ea6d6b01fa032029225255aa37a83'

EXPECTED_REFS=[
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'IsHappenPowerCompetition','caller_token':'0x06004FD3','caller_rva':'0x002F8D90','caller_code_size':40,'caller_code_sha256':'6d6d6ede32b0294d70267f18c929adf5a196a0ca8f720d77547385aa1df8c414','call_il':'0x0016','opcode':'callvirt'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'MakeRapidPushTbl','caller_token':'0x06004FD4','caller_rva':'0x002F8DC4','caller_code_size':308,'caller_code_sha256':'63b284583be3198f0647d16649fe43126b7f5c5d0b0c6a5c2ba73ad233530db7','call_il':'0x0032','opcode':'callvirt'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple','caller_token':'0x06004FE4','caller_rva':'0x002F9E9C','caller_code_size':709,'caller_code_sha256':'221fc977746121dd811fe1d13e59502c160992648d03561b81e6b7555e04ea42','call_il':'0x0064','opcode':'callvirt'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Check_FoxSleep','caller_token':'0x06005028','caller_rva':'0x002FF9E0','caller_code_size':359,'caller_code_sha256':'bb62bc0b7810c42b19734ccb5523d60cc4dd70c32c896c314b58d1aa07213bae','call_il':'0x0076','opcode':'callvirt'}
]

class E(RuntimeError): pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''): h.update(c)
    return h.hexdigest()

def compressed_uint(blob,pos):
    x=blob[pos]
    if x<0x80: return x,pos+1
    if x<0xC0: return ((x&0x3f)<<8)|blob[pos+1],pos+2
    return ((x&0x1f)<<24)|(blob[pos+1]<<16)|(blob[pos+2]<<8)|blob[pos+3],pos+4

def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[
        (bytes([0x28])+needle,'call'),(bytes([0x6f])+needle,'callvirt'),
        (bytes([0x73])+needle,'newobj'),(bytes([0x27])+needle,'jmp'),
        (bytes([0xfe,0x06])+needle,'ldftn'),(bytes([0xfe,0x07])+needle,'ldvirtftn')
    ]
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
                    'call_il':f'0x{x:04X}',
                    'opcode':opname
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
    if (raw,rva,impl,flags,name,sig,plist,owner)!=(ROW,RVA,0,FLAGS,'GetCOMLevelData',SIG,PARAM_RID,('COMLevelDataManager','')):
        raise E('method metadata')
    ho=base.off(ss,RVA)
    if pe[ho:ho+1].hex()!=TINY_HEADER or pe[ho]>>2!=9: raise E('tiny header')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')
    if body!=bytes([0x02,0x7b,0x39,0x0d,0x00,0x04,0x03,0x9a,0x2a]): raise E('instruction bytes')

    sigb=bytes.fromhex(SIG)
    if sigb[:3]!=bytes([0x20,0x01,0x12]): raise E('signature prefix')
    coded,pos=compressed_uint(sigb,3)
    if (coded&3)!=0 or (coded>>2)!=RETURN_TYPE_RID or sigb[pos:]!=bytes([0x08]): raise E('signature types')
    traw,tname,tns,textends,tfl,tml=drop.typedef(pe,rows,s,ix,z,o,sb,RETURN_TYPE_RID)
    if (traw,tname,tns)!=(RETURN_TYPE_ROW,'COMLevelData',''): raise E('return TypeDef')

    pp=o[8]+(PARAM_RID-1)*z[8]
    praw=pe[pp:pp+z[8]]
    if praw.hex()!=PARAM_ROW: raise E('Param row')
    if struct.unpack_from('<H',praw,0)[0]!=0 or struct.unpack_from('<H',praw,2)[0]!=1: raise E('Param flags/sequence')
    ni,_=base.rd(pe,pp+4,s)
    if base.s_at(pe,sb,ni)!='lv': raise E('Param name')

    if drop.field(pe,s,b,z,o,sb,bb,fm,FIELD)!=(FIELD_ROW,('COMLevelDataManager',''),'comLevelData',FIELD_SIG):
        raise E('field metadata')
    amap=[{'il':'0x0001','opcode':'ldfld','token':'0x04000D39'}]
    if body[1]!=0x7b or struct.unpack_from('<I',body,2)[0]!=FIELD: raise E('field access')
    if hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_ACCESS_DIGEST:
        raise E('field access digest')

    if drop.calls(body)!=[]: raise E('unexpected call surface')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('direct reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr})
    cd=hashlib.sha256((''.join(x+'\n' for x in callers)).encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {
      'code_size':9,'code_sha256':SHA,'canonical_internal_methoddef_reference_count':0,
      'external_memberref_count':0,'direct_reference_count':4,'direct_caller_method_count':4,
      'reference_map_sha256':rd
    }

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'COMLevelDataManager.GetCOMLevelData':0,
      'PlayerController_AI.IsHappenPowerCompetition':0,
      'PlayerController_AI.MakeRapidPushTbl':0,
      'PlayerController_AI.Process_Grapple':0,
      'PlayerController_AI.Check_FoxSleep':0
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
        print('PROVE_COMLEVELDATAMANAGER_GET_COM_LEVEL_DATA: PASS'); return 0
    except Exception as e:
        print('PROVE_COMLEVELDATAMANAGER_GET_COM_LEVEL_DATA: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
