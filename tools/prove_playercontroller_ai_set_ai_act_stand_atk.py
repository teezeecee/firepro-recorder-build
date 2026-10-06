#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_set_ai_act_go_front_grapple as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004FA5; RVA=0x002F606E
ROW='6e602f000000810066350a00cbcd0200ba3a'; SIG='20020111a7cc08'; FLAGS=0x0081; HEADER=0x46
BODY=bytes.fromhex('021f1704289d4f000602037d4e6100042a')
SHA='6cf419de21ddef2550f679f589ce58fe6b76a8b665220f170bc8a739fa93ef2f'
PARAM_ROWS=['00000100976d0700','00000200d7610700']; PARAM_NAMES=['atk_kind','tm']
ENUM_RID=2547; ENUM_ROW='0301000086790000000000004503a2612d50'
FIELD=0x0400614E; FIELD_ROW='0100dbf2030001000000'; FIELD_SIG='0608'
CHILD=0x06004F9D; CHILD_SHA='58725b1757df7dd4bb511637f82b17f0ec95140b0a213f420cf88b318d04d065'
REF_DIGEST='728ef6545f9a114d98ea24ad7e20b2e22c9a29d494c187596f035415678f8f38'
CALLER_DIGEST='00401fd225d658d3e6e796b6a8fbd79090c46d0544edb505dde81f55bd6d5124'
EXPECTED_REFS=[
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'vpc_wait2','caller_token':'0x06004FCD','caller_rva':'0x002F8994','caller_code_size':146,'caller_code_sha256':'3741d325192e27e78fa06d59a18679c12f3ac2ef2073fe017db7a8217ed07393','call_il':'0x008B','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x014C','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x01E3','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x01F1','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x01FF','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Far','caller_token':'0x06004FF6','caller_rva':'0x002FB820','caller_code_size':565,'caller_code_sha256':'c8e5ed6f584710bef2d8b8522a13843c1ff8f23e5c5149748add48816b79d646','call_il':'0x0105','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Far','caller_token':'0x06004FF6','caller_rva':'0x002FB820','caller_code_size':565,'caller_code_sha256':'c8e5ed6f584710bef2d8b8522a13843c1ff8f23e5c5149748add48816b79d646','call_il':'0x0224','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands','caller_token':'0x06004FFA','caller_rva':'0x002FBC78','caller_code_size':511,'caller_code_sha256':'06e26cc768d8d7b287fa87e2462328a6c46211fec42aa4a56f4872d5281f017f','call_il':'0x007D','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands','caller_token':'0x06004FFA','caller_rva':'0x002FBC78','caller_code_size':511,'caller_code_sha256':'06e26cc768d8d7b287fa87e2462328a6c46211fec42aa4a56f4872d5281f017f','call_il':'0x00CF','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands','caller_token':'0x06004FFA','caller_rva':'0x002FBC78','caller_code_size':511,'caller_code_sha256':'06e26cc768d8d7b287fa87e2462328a6c46211fec42aa4a56f4872d5281f017f','call_il':'0x0110','opcode':'call'},
{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_Second','caller_token':'0x0600500E','caller_rva':'0x002FD73C','caller_code_size':646,'caller_code_sha256':'eaa00ca466ac8ed88940cb307ffb3af44e1b89393d29b5a1c4a32eaf4120a1a8','call_il':'0x0277','opcode':'call'}]
E=base.E
def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[(b'\x28'+needle,'call'),(b'\x6f'+needle,'callvirt'),(b'\x73'+needle,'newobj'),(b'\x27'+needle,'jmp'),(b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')]
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
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'SetAIAct_StandAtk',SIG,('PlayerController_AI','')): raise E('method metadata')
    if pe[base.off(ss,RVA)]!=HEADER or body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body/header')
    nxt=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)
    if nxt[6]!=plist+2: raise E('parameter range')
    for idx,(rowhex,pname) in enumerate(zip(PARAM_ROWS,PARAM_NAMES)):
        pp=o[8]+(plist+idx-1)*z[8]
        if pe[pp:pp+z[8]].hex()!=rowhex: raise E('parameter row')
        ni,_=base.rd(pe,pp+4,s)
        if base.s_at(pe,sb,ni)!=pname: raise E('parameter name')
    traw,tname,tns,_,_,_=base.typedef(pe,rows,s,ix,z,o,sb,ENUM_RID)
    if (traw,tname,tns)!=(ENUM_ROW,'StandAtkEnum',''): raise E('StandAtkEnum TypeDef')
    if base.field(pe,s,b,z,o,sb,bb,fm,FIELD)!=(FIELD_ROW,('PlayerController_AI',''),'aiActPrm',FIELD_SIG): raise E('field')
    if body[0:4]!=bytes([0x02,0x1f,0x17,0x04]) or body[4]!=0x28 or struct.unpack_from('<I',body,5)[0]!=CHILD: raise E('call flow')
    child=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if child[4]!='SetAIAct' or child[7]!=('PlayerController_AI','') or len(child[9])!=102 or hashlib.sha256(child[9]).hexdigest()!=CHILD_SHA: raise E('FACT-0043 child')
    if body[9:11]!=bytes([0x02,0x03]) or body[11]!=0x7d or struct.unpack_from('<I',body,12)[0]!=FIELD or body[16]!=0x2a: raise E('field write/ret')
    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr}); cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)
    return {'code_size':17,'code_sha256':SHA,'canonical_child_method_count':1,'direct_reference_count':11,'direct_caller_method_count':5,'reference_map_sha256':rd}
def verify_r6(path):
    if base.sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={'PlayerController_AI.SetAIAct_StandAtk':0,'PlayerController_AI.SetAIAct':0,'PlayerController_AI.vpc_wait2':0,'PlayerController_AI.Process_OpponentStands_Stun':0,'PlayerController_AI.Process_OpponentStands_Far':0,'PlayerController_AI.Process_OpponentStands':0,'PlayerController_AI.Process_Second':0}
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
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True)); print('PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_STAND_ATK: PASS'); return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_STAND_ATK: FAIL'); print(str(e)); return 1
if __name__=='__main__': raise SystemExit(main())
