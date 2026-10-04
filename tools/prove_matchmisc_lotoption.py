#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x0600495B
RVA=0x002B0230
ROW='30022b000000960095fb090089af01003636'
SIG='0001081d08'
FLAGS=0x0096
HEADER='133003003400000073000011'
BODY=bytes.fromhex('161f64287b4900060a028e690b160c160d381300000008020994580c06083c02000000092a0917580d09073fe6ffffff0717592a')
SHA='6d094b5b2ba805a275e1d97aa553088f42a9dbe4937cb83440b230ade378851f'

PARAM_ROW='000001006f4f0700'
LOCAL_SIG_TOKEN=0x11000073
LOCAL_SIG_ROW='755f0100'
LOCAL_SIG_BLOB='070408080808'

CHILD=0x0600497B
CHILD_SIG='0002080808'
CHILD_SHA='d6ed5dd5c1cdf595ca459ddc1c740ce66543e9630786cfdc9bf3404247f643f6'
CALL_DIGEST='7f29a5a0588dcc84dee0116cdfa0835c9b4e05f281e4738922ef6f77024240b5'

EXPECTED_REFS=[
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple_Front','caller_token':'0x06004FE1','caller_rva':'0x002F9AB8','caller_code_size':407,'caller_code_sha256':'dd85a5c42843eb544814588585369b933af988f9a25a544093517603bde570ec','call_il':'0x0158','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple_BackAtk','caller_token':'0x06004FE3','caller_rva':'0x002F9D40','caller_code_size':334,'caller_code_sha256':'cd3deb24c9c49730460a7d595105d48c8d342600d53947160adc8feaffd546b0','call_il':'0x00CB','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple','caller_token':'0x06004FE4','caller_rva':'0x002F9E9C','caller_code_size':709,'caller_code_sha256':'221fc977746121dd811fe1d13e59502c160992648d03561b81e6b7555e04ea42','call_il':'0x01A3','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple','caller_token':'0x06004FE4','caller_rva':'0x002F9E9C','caller_code_size':709,'caller_code_sha256':'221fc977746121dd811fe1d13e59502c160992648d03561b81e6b7555e04ea42','call_il':'0x0204','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple','caller_token':'0x06004FE4','caller_rva':'0x002F9E9C','caller_code_size':709,'caller_code_sha256':'221fc977746121dd811fe1d13e59502c160992648d03561b81e6b7555e04ea42','call_il':'0x024A','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Grapple','caller_token':'0x06004FE4','caller_rva':'0x002F9E9C','caller_code_size':709,'caller_code_sha256':'221fc977746121dd811fe1d13e59502c160992648d03561b81e6b7555e04ea42','call_il':'0x0290','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OnCorner','caller_token':'0x06004FE7','caller_rva':'0x002FA500','caller_code_size':368,'caller_code_sha256':'06a72d71e5418f10209cb6731fae3bae41c98d4a1b98a759f5e6ec2e63fc53bf','call_il':'0x0109','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_DownAttack','caller_token':'0x06004FEA','caller_rva':'0x002FA718','caller_code_size':252,'caller_code_sha256':'52ce42d4aae99b7986e46e5efdb1bc462f061e3b235c40346c237942b745a211','call_il':'0x00B7','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_Dive','caller_token':'0x06004FED','caller_rva':'0x002FA89C','caller_code_size':366,'caller_code_sha256':'113579d5d828a5604a57b58e74cd969ad4516645249c10fe412a7d5f03a32cac','call_il':'0x0093','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_Dive','caller_token':'0x06004FED','caller_rva':'0x002FA89C','caller_code_size':366,'caller_code_sha256':'113579d5d828a5604a57b58e74cd969ad4516645249c10fe412a7d5f03a32cac','call_il':'0x00A5','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_Dive_Stun','caller_token':'0x06004FEE','caller_rva':'0x002FAA18','caller_code_size':505,'caller_code_sha256':'8d5273fae9c0e6ba9fb560dd8e34d26f3c95488a620abc08c74271f6deb513ec','call_il':'0x00A7','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_Dive_Stun','caller_token':'0x06004FEE','caller_rva':'0x002FAA18','caller_code_size':505,'caller_code_sha256':'8d5273fae9c0e6ba9fb560dd8e34d26f3c95488a620abc08c74271f6deb513ec','call_il':'0x00B9','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_Center','caller_token':'0x06004FEF','caller_rva':'0x002FAC20','caller_code_size':416,'caller_code_sha256':'1410b445d0837d6040c935b8480105867ff163b67a92c97e4f2b5b9ab1d720b2','call_il':'0x0082','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown','caller_token':'0x06004FF0','caller_rva':'0x002FADCC','caller_code_size':662,'caller_code_sha256':'47e35ee574cf3791c43a6aa4b3146bb8004ef595b87cbe5722ee9ff63540e05e','call_il':'0x009F','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_OpponentOutOfRing','caller_token':'0x06004FF1','caller_rva':'0x002FB070','caller_code_size':835,'caller_code_sha256':'c03a26efa47d9bf1adb178df7fbbbc4557e348b2f28ab393b744d9e8f1c53e6c','call_il':'0x00BB','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_OpponentOutOfRing','caller_token':'0x06004FF1','caller_rva':'0x002FB070','caller_code_size':835,'caller_code_sha256':'c03a26efa47d9bf1adb178df7fbbbc4557e348b2f28ab393b744d9e8f1c53e6c','call_il':'0x00E1','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_AfterHammerThrow','caller_token':'0x06004FF2','caller_rva':'0x002FB3C0','caller_code_size':248,'caller_code_sha256':'f417f4eab0e62c6e31057c8c5123b17c930240b8a0691685c70a1fc40ca4e7d3','call_il':'0x0075','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_LeanOnCorner','caller_token':'0x06004FF3','caller_rva':'0x002FB4C4','caller_code_size':191,'caller_code_sha256':'28bfe6a69c54e94e619895bbbeda071dd3c66089585068a17eeacaafc28ee1d8','call_il':'0x006F','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x0045','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x00CD','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x0195','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Far','caller_token':'0x06004FF6','caller_rva':'0x002FB820','caller_code_size':565,'caller_code_sha256':'c8e5ed6f584710bef2d8b8522a13843c1ff8f23e5c5149748add48816b79d646','call_il':'0x009B','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Far','caller_token':'0x06004FF6','caller_rva':'0x002FB820','caller_code_size':565,'caller_code_sha256':'c8e5ed6f584710bef2d8b8522a13843c1ff8f23e5c5149748add48816b79d646','call_il':'0x0113','opcode':'call'},
 {'caller_type':'WeaponMan','caller_namespace':'','caller_method':'GetGenerateWeaponKind','caller_token':'0x06006ACE','caller_rva':'0x0043560E','caller_code_size':13,'caller_code_sha256':'227467008fa96c68f2acce6672b5d1e78c57c24453499501e32b7f6a16b42d4d','call_il':'0x0007','opcode':'call'}
]
REF_DIGEST='3e5bf66dd56899a8fe42ff08972f56478275e3887dca0a61848d99426fbac7cc'
CALLER_DIGEST='afa0d52d08d97e2072d7561b6bcbf3ea02737d28587f66785e8302a5cd14eb38'

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
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'LotOption',SIG,('MatchMisc','')):
        raise E('method metadata')
    next_plist=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]
    if next_plist-plist!=1: raise E('parameter count')

    p=o[8]+(plist-1)*z[8]
    rawp=pe[p:p+z[8]]
    fl=struct.unpack_from('<H',rawp,0)[0]
    sq=struct.unpack_from('<H',rawp,2)[0]
    q2=p+4
    ni,_=base.rd(pe,q2,s)
    if (rawp.hex(),fl,sq,base.s_at(pe,sb,ni))!=(PARAM_ROW,0,1,'rate_tbl'):
        raise E('rate_tbl parameter')

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

    got=drop.calls(body)
    if got!=[(0x0003,0x28,CHILD)]: raise E('call surface '+repr(got))
    cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if cm[4]!='Range' or cm[5]!=CHILD_SIG or cm[7]!=('MatchRandom','') or len(cm[9])!=30 or hashlib.sha256(cm[9]).hexdigest()!=CHILD_SHA:
        raise E('FACT-0032 child identity')
    core=[{'il':'0x0003','opcode':'call','token':'0x0600497B'}]
    if hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=CALL_DIGEST:
        raise E('call digest')

    if body[0:8]!=bytes.fromhex('161f64287b490006'): raise E('Range 0,100')
    if body[0x0011]!=0x38 or target4(body,0x0011)!=0x0029: raise E('initial loop branch')
    if body[0x0016:0x001c]!=bytes.fromhex('08020994580c'): raise E('running total')
    if body[0x001c:0x001e]!=bytes.fromhex('0608'): raise E('sample/total load')
    if body[0x001e]!=0x3c or target4(body,0x001e)!=0x0025: raise E('sample threshold branch')
    if body[0x0023:0x0025]!=bytes.fromhex('092a'): raise E('index return')
    if body[0x0025:0x0029]!=bytes.fromhex('0917580d'): raise E('index increment')
    if body[0x0029:0x002b]!=bytes.fromhex('0907'): raise E('loop compare')
    if body[0x002b]!=0x3f or target4(body,0x002b)!=0x0016: raise E('loop back branch')
    if body[0x0030:0x0034]!=bytes.fromhex('0717592a'): raise E('length minus one return')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr},key=lambda x:int(x,16))
    cd=hashlib.sha256(''.join(x+'\n' for x in callers).encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    parent=[x for x in rr if x['caller_token']=='0x06004FF2']
    if len(parent)!=1 or parent[0]['call_il']!='0x0075': raise E('hammer-throw parent bridge')

    return {
      'code_size':52,'code_sha256':SHA,
      'canonical_internal_methoddef_reference_count':1,
      'external_memberref_method_call_count':0,
      'direct_reference_count':24,'direct_caller_method_count':15,
      'reference_map_sha256':rd
    }

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'MatchMisc.LotOption':0,
      'MatchRandom.Range':0,
      'PlayerController_AI.Process_OpponentStands_AfterHammerThrow':0
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
        print('PROVE_MATCHMISC_LOTOPTION: PASS')
        return 0
    except Exception as e:
        print('PROVE_MATCHMISC_LOTOPTION: FAIL')
        print(str(e))
        return 1

if __name__=='__main__': raise SystemExit(main())
