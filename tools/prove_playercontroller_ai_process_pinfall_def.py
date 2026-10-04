#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06005023
RVA=0x002FF78C
ROW='8cf72f0000008100ea3f0a00db490000de3a'
SIG='200002'
FLAGS=0x0081
HEADER='133003006300000000000000'
BODY=bytes.fromhex('027b4a6100047b496000043a02000000162a027b4a6100047b526000043902000000162a027b646100043a0d0000000228d44f000602177d64610004027b63610004027b656100041f3c5d913908000000021f207d18610004021f207d17610004172a')
SHA='8cd99966c2f677c3c5adb0b93e5ff520f7cccecc1d4c80f260694ad88c091a0a'

FIELDS={
 0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
 0x04006049:('Player','isPinfallDef','060071e7030008000000','0602'),
 0x04006052:('Player','isLose','06000ee8030008000000','0602'),
 0x04006164:('PlayerController_AI','initializedRapidPushTbl','010011f4030008000000','0602'),
 0x04006163:('PlayerController_AI','rapidPushTbl','010004f4030084090000','061d02'),
 0x04006165:('PlayerController_AI','frmCnt','010029f4030001000000','0608'),
 0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c'),
 0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c')
}
ACCESS=[
 (0x0001,'ldfld',0x0400614A),(0x0006,'ldfld',0x04006049),
 (0x0013,'ldfld',0x0400614A),(0x0018,'ldfld',0x04006052),
 (0x0025,'ldfld',0x04006164),(0x0037,'stfld',0x04006164),
 (0x003D,'ldfld',0x04006163),(0x0043,'ldfld',0x04006165),
 (0x0054,'stfld',0x04006118),(0x005C,'stfld',0x04006117)
]
FIELD_ACCESS_DIGEST='62def3dc7a912f13980e15fee2bf5c126ec580ae7708489859903cbb18ef75b5'

CHILD=0x06004FD4
CHILD_SHA='63b284583be3198f0647d16649fe43126b7f5c5d0b0c6a5c2ba73ad233530db7'
CALL_DIGEST='13fbb5ce22b7d241c4f2425461755f7b0fc66b497be3e43ea0e3386a0b069418'

EXPECTED_REFS=[{
 'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Update',
 'caller_token':'0x0600502B','caller_rva':'0x002FFC68','caller_code_size':984,
 'caller_code_sha256':'6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9',
 'call_il':'0x01C1','opcode':'call'
}]
REF_DIGEST='074fc86e10e9aca5ac69ddab4f0a8a69a06a5bab38fb35cf79f99e105232a27d'
CALLER_DIGEST='8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63'

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
    ss,q=base.secs(pe); st,hs,rows,tp=base.mdstreams(pe,ss,q); s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]; fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

    md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_PinfallDef',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    if drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]!=plist: raise E('unexpected parameters')

    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    fs=struct.unpack_from('<H',pe,ho)[0]
    if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+4)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,3,99,0):
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    for tok,(own,nm,row,sg) in FIELDS.items():
        if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg): raise E('field '+hex(tok))
    opbytes={'ldfld':0x7b,'stfld':0x7d}
    amap=[]
    for il,opn,tok in ACCESS:
        if body[il]!=opbytes[opn] or struct.unpack_from('<I',body,il+1)[0]!=tok: raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opn,'token':f'0x{tok:08X}'})
    if hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_ACCESS_DIGEST:
        raise E('field access digest')

    if body[0x000B]!=0x3a or drop.target4(body,0x000B)!=0x0012: raise E('isPinfallDef gate')
    if body[0x0010:0x0012]!=bytes([0x16,0x2a]): raise E('pinfall false return')
    if body[0x001D]!=0x39 or drop.target4(body,0x001D)!=0x0024: raise E('isLose gate')
    if body[0x0022:0x0024]!=bytes([0x16,0x2a]): raise E('lose true return')
    if body[0x002A]!=0x3a or drop.target4(body,0x002A)!=0x003C: raise E('initialized gate')
    if body[0x0030]!=0x28 or struct.unpack_from('<I',body,0x0031)[0]!=CHILD: raise E('MakeRapidPushTbl call')
    if body[0x0035:0x003C]!=bytes.fromhex('02177d64610004'): raise E('initialized write')
    if body[0x0048:0x004C]!=bytes([0x1f,60,0x5d,0x91]): raise E('rapidPushTbl modulo probe')
    if body[0x004C]!=0x39 or drop.target4(body,0x004C)!=0x0059: raise E('probe false branch')
    if body[0x0051:0x0059]!=bytes.fromhex('021f207d18610004'): raise E('conditional padPush raw 32 write')
    if body[0x0059:0x0061]!=bytes.fromhex('021f207d17610004'): raise E('unconditional padOn raw 32 write')
    if body[0x0061:0x0063]!=bytes([0x17,0x2a]): raise E('true return')

    got=drop.calls(body)
    if got!=[(0x0030,0x28,CHILD)]: raise E('call surface '+repr(got))
    cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if cm[4]!='MakeRapidPushTbl' or cm[7]!=('PlayerController_AI','') or len(cm[9])!=308 or hashlib.sha256(cm[9]).hexdigest()!=CHILD_SHA:
        raise E('FACT-0238 child identity')
    core=[{'il':'0x0030','opcode':'call','token':'0x06004FD4'}]
    if hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=CALL_DIGEST:
        raise E('call digest')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    cd=hashlib.sha256(('0x0600502B\n').encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {
      'code_size':99,'code_sha256':SHA,'canonical_internal_methoddef_reference_count':1,
      'external_memberref_method_call_count':0,'direct_reference_count':1,
      'direct_caller_method_count':1,'reference_map_sha256':rd
    }

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'PlayerController_AI.Process_PinfallDef':0,
      'PlayerController_AI.MakeRapidPushTbl':0,
      'PlayerController_AI.Update':0
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
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_PINFALL_DEF: PASS'); return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_PINFALL_DEF: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
