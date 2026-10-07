#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_set_ai_act_go_front_grapple as base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'; DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'; EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004FF4; RVA=0x002FB590; ROW='90b52f0000008100443c0a00db490000d93a'; SIG='200002'
BODY=bytes.fromhex('7efa610004027b4a6100047bb15f00046f655000060a067bb75f00041f154002000000172a067bc15f00042875490006228fc215404102000000172a067bb75f00041f0b4019000000067b50600004390e000000067bd05f0004163e02000000172a162a')
SHA='6be0ad496b10e6b013a20cf29ce0fa8f50b2c835aad2392dee083cfedca721e0'
REF_DIGEST='3f47cd3c35c7650d8eefd0257ecac6fbfe42a0bbe93de424d53d09031c12c70e'; CALLER_DIGEST='3376d25c6c7dc91627ba537f75e795eedc2f074cb2fd9a18e2214dcc818c3e8e'
FIELD_DIGEST='75d9689017fbad25ea3b1958f2f042e804b4c82925057ff5a82c208dbd6903b7'; CALL_DIGEST='e5884ecbd4e1dad1e85c32298bef1b0c1f9126898265dd2d18cb959082a2f7e1'
class E(RuntimeError): pass
def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T); pats=[(b'\x28'+needle,'call'),(b'\x6f'+needle,'callvirt'),(b'\x73'+needle,'newobj'),(b'\x27'+needle,'jmp'),(b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid; md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok); body=md[9]
        if not body: continue
        for pat,opname in pats:
            pos=0
            while True:
                x=body.find(pat,pos)
                if x<0: break
                out.append({'caller_type':md[7][0] if md[7] else None,'caller_namespace':md[7][1] if md[7] else None,'caller_method':md[4],'caller_token':f'0x{tok:08X}','caller_rva':f'0x{md[1]:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname}); pos=x+1
    out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode'])); return out
def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=base.secs(pe); st,hs,rows,tp=base.mdstreams(pe,ss,q); s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]; fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T); raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,0x0081,'IsTargetStunned',SIG,('PlayerController_AI','')): raise E('method metadata')
    if base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]!=plist: raise E('parameter count')
    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!='13300200640000008e020011': raise E('fat header')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')
    rid=0x28E; p=o[17]+(rid-1)*z[17]; rawloc=pe[p:p+z[17]]; si,_=base.rd(pe,p,b)
    if rawloc.hex()!='6b940100' or base.blob(pe,bb,si).hex()!='070112a788': raise E('local sig')
    traw,tname,tns,_,_,_=base.typedef(pe,rows,s,ix,z,o,sb,2530)
    if (traw,tname,tns)!=('01001000fd480000000000005500565fa74e','Player',''): raise E('Player TypeDef')
    fields={0x040061FA:('160006220100cf380000',('PlayerMan',''),'inst','0612a818'),0x0400614A:('0100b7f203005e190000',('PlayerController_AI',''),'PlObj','0612a788'),0x04005FB1:('060071e0030001000000',('Player',''),'TargetPlIdx','0608'),0x04005FB7:('06006e000000da370000',('Player',''),'State','0611a828'),0x04005FC1:('0600ece0030014000000',('Player',''),'BP','060c'),0x04006050:('0600e5e7030008000000',('Player',''),'isStandingStunOK','0602'),0x04005FD0:('060046e1030001000000',('Player',''),'StunTime','0608')}
    for tok,exp in fields.items():
        if base.field(pe,s,b,z,o,sb,bb,fm,tok)!=exp: raise E('field '+hex(tok))
    fa=[{'il':'0x0000','opcode':'ldsfld','token':'0x040061FA'},{'il':'0x0006','opcode':'ldfld','token':'0x0400614A'},{'il':'0x000B','opcode':'ldfld','token':'0x04005FB1'},{'il':'0x0017','opcode':'ldfld','token':'0x04005FB7'},{'il':'0x0026','opcode':'ldfld','token':'0x04005FC1'},{'il':'0x003D','opcode':'ldfld','token':'0x04005FB7'},{'il':'0x004A','opcode':'ldfld','token':'0x04006050'},{'il':'0x0055','opcode':'ldfld','token':'0x04005FD0'}]
    if hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_DIGEST: raise E('field digest')
    child_specs=[(0x0010,0x6f,0x06005065,'PlayerMan','GetPlObj',25,'32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8'),(0x002B,0x28,0x06004975,'MatchMisc','GetParamRate',16,'60de3a243171244b6e09508e9a73f00d82aa76207ad3e8dd046322bc7b849e6c')]
    for il,op,tok,own,nm,sz,sha in child_specs:
        if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok: raise E('call '+hex(il))
        cm=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        if cm[7]!=(own,'') or cm[4]!=nm or len(cm[9])!=sz or hashlib.sha256(cm[9]).hexdigest()!=sha: raise E('child '+hex(tok))
    core=[{'il':'0x0010','opcode':'callvirt','token':'0x06005065'},{'il':'0x002B','opcode':'call','token':'0x06004975'}]
    if hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=CALL_DIGEST: raise E('call digest')
    checks=[(0x001C,b'\x1f\x15'),(0x001E,b'\x40\x02\x00\x00\x00'),(0x0030,b'\x22\x8f\xc2\x15\x40'),(0x0035,b'\x41\x02\x00\x00\x00'),(0x0042,b'\x1f\x0b'),(0x0044,b'\x40\x19\x00\x00\x00'),(0x004F,b'\x39\x0e\x00\x00\x00'),(0x005A,b'\x16'),(0x005B,b'\x3e\x02\x00\x00\x00')]
    for il,bs in checks:
        if body[il:il+len(bs)]!=bs: raise E('branch/raw '+hex(il))
    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    expected=[{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'AIActFunc_GoBackGrapple','caller_token':'0x06004FB1','caller_rva':'0x002F634C','caller_code_size':235,'caller_code_sha256':'05aa37f29b638f8da45743303251598eea9a5bf501388a75d7f0208ea0a2175c','call_il':'0x0017','opcode':'call'},{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x0033','opcode':'call'}]
    if rr!=expected: raise E('reference surface '+repr(rr))
    refd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if refd!=REF_DIGEST: raise E('reference digest '+refd)
    cd=hashlib.sha256(('0x06004FB1\n0x06004FF5\n').encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)
    return {'code_size':100,'code_sha256':SHA,'canonical_child_method_count':2,'direct_reference_count':2,'direct_caller_method_count':2,'reference_map_sha256':refd}
def verify_r6(path):
    if base.sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={'PlayerController_AI.IsTargetStunned':0,'PlayerMan.GetPlObj':0,'MatchMisc.GetParamRate':0,'PlayerController_AI.AIActFunc_GoBackGrapple':0,'PlayerController_AI.Process_OpponentStands_Stun':0}
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
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True)); print('PROVE_PLAYERCONTROLLER_AI_IS_TARGET_STUNNED: PASS'); return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_IS_TARGET_STUNNED: FAIL'); print(str(e)); return 1
if __name__=='__main__': raise SystemExit(main())
