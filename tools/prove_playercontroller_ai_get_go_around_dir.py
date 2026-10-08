#!/usr/bin/env python3
"""Byte-locked GetGoAroundDir audit. Raw proprietary source files stay outside Git."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
T=0x06004FD7
ROW='14912f0000008100d6390a0031cf0200ce3a'
SIG='200011a7dc'
HEADER='133002007e0000008e020011'
BODY=bytes.fromhex('7efa610004027b4a6100047bb15f00046f655000060a027b4a6100047caa5f00047b0a00000a067caa5f00047b0a00000a4424000000027b4a6100047caa5f00047b0900000a067caa5f00047b0900000a4202000000172a162a027b4a6100047caa5f00047b0900000a067caa5f00047b0900000a4202000000162a172a')
SHA='6b1b83ca72c103a69a8f1ee79dfef7e6d7024e829b9a338b9589b198d118ab10'
FIELDS_SHA='a48fdfad43d24078fde692cf854dc544d7e73db494ab9acdaf097ffaecfc34af'
BR_SHA='89168870fe4dce524cadca483afbac2b8e65d3c62afc3b68265e6c74d42ec1a2'
CALL_SHA='13b4ef5227d073a59ac75ece81a4948af794e5f04580d44e10d275866565883c'
REF_SHA='f0445964c004ae70ce4d578835e89c0356d8bf43e0f3d6b184548137d8095a60'
CALLER_SHA='f5ba886b8ff566cd53e8d0c9c16e7ae72eabe7372dcc5f3bc427e9576e777540'

class E(RuntimeError):pass
def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def references(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[(b'\x28'+needle,'call'),(b'\x6f'+needle,'callvirt'),(b'\x73'+needle,'newobj'),(b'\x27'+needle,'jmp'),(b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')]
    found=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        m=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        body=m[9]
        if not body:continue
        for pat,op in pats:
            pos=0
            while True:
                at=body.find(pat,pos)
                if at<0:break
                found.append({'caller_type':m[7][0] if m[7] else None,'caller_namespace':m[7][1] if m[7] else None,'caller_method':m[4],'caller_token':f'0x{tok:08X}','caller_rva':f'0x{m[1]:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{at:04X}','opcode':op})
                pos=at+1
    return sorted(found,key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=8171008 or hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E('DLL source identity')
    ss,q=base.secs(pe);st,hs,rows,tp=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0];bb=st['#Blob'][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    m=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,_,body=m
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,0x002F9114,0,0x0081,'GetGoAroundDir',SIG,('PlayerController_AI','')):raise E('MethodDef metadata')
    if base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]!=plist:raise E('parameter count')
    if pe[base.off(ss,rva):base.off(ss,rva)+12].hex()!=HEADER:raise E('fat header')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:raise E('body')
    rid=0x28E; p=o[17]+(rid-1)*z[17]; rawloc=pe[p:p+z[17]]
    si,_=base.rd(pe,p,b)
    if rawloc.hex()!='6b940100' or base.blob(pe,bb,si).hex()!='070112a788':raise E('local Player signature')
    fields={
      0x040061FA:('160006220100cf380000',('PlayerMan',''),'inst','0612a818'),
      0x0400614A:('0100b7f203005e190000',('PlayerController_AI',''),'PlObj','0612a788'),
      0x04005FB1:('060071e0030001000000',('Player',''),'TargetPlIdx','0608'),
      0x04005FAA:('060039e0030070000000',('Player',''),'PlPos','061119')}
    for tok,expect in fields.items():
        if base.field(pe,s,b,z,o,sb,bb,fm,tok)!=expect:raise E('Field metadata '+hex(tok))
    mr=[(0x0A000009,'31000000dfb6000014000000','x','060c'),(0x0A00000A,'31000000e1b6000014000000','y','060c')]
    ps=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=8192 else 2
    for tok,row,nm,sig2 in mr:
        p=o[10]+((tok&0xffffff)-1)*z[10]
        ni,j=base.rd(pe,p+ps,s);bi,_=base.rd(pe,j,b)
        if (pe[p:p+z[10]].hex(),base.s_at(pe,sb,ni),base.blob(pe,bb,bi).hex())!=(row,nm,sig2):raise E('MemberRef field '+hex(tok))
    # Full sequential decode for this exact opcode alphabet, eliminating operand false positives.
    opnames={0x7e:'ldsfld',0x02:'ldarg.0',0x7b:'ldfld',0x6f:'callvirt',0x0a:'stloc.0',0x06:'ldloc.0',0x7c:'ldflda',0x44:'blt.un',0x42:'bgt.un',0x17:'ldc.i4.1',0x16:'ldc.i4.0',0x2a:'ret'}
    instructions=[];p=0
    while p<len(body):
        opc=body[p]
        if opc not in opnames:raise E('unexpected IL opcode '+hex(opc))
        width=5 if opc in (0x7e,0x7b,0x6f,0x7c,0x44,0x42) else 1
        if p+width>len(body):raise E('truncated IL')
        val=struct.unpack_from('<I',body,p+1)[0] if width==5 else None
        if opc in (0x44,0x42): val=p+5+struct.unpack_from('<i',body,p+1)[0]
        instructions.append((p,opnames[opc],val));p+=width
    fld=[{'il':f'0x{i:04X}','opcode':op,'token':f'0x{val:08X}'} for i,op,val in instructions if op in ('ldsfld','ldfld','ldflda') and val>>24==4]
    if digest(fld)!=FIELDS_SHA or len(fld)!=12:raise E('field access map')
    ext=[(i,op,val) for i,op,val in instructions if op=='ldfld' and val>>24==0x0A]
    if ext!=[(0x21,'ldfld',0x0A00000A),(0x2c,'ldfld',0x0A00000A),(0x41,'ldfld',0x0A000009),(0x4c,'ldfld',0x0A000009),(0x65,'ldfld',0x0A000009),(0x70,'ldfld',0x0A000009)]:raise E('MemberRef fields')
    calls=[{'il':f'0x{i:04X}','opcode':op,'token':f'0x{val:08X}'} for i,op,val in instructions if op in ('callvirt',)]
    if digest(calls)!=CALL_SHA or calls!=[{'il':'0x0010','opcode':'callvirt','token':'0x06005065'}]:raise E('internal calls')
    child=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06005065)
    if child[7]!=('PlayerMan','') or child[4]!='GetPlObj' or len(child[9])!=25 or hashlib.sha256(child[9]).hexdigest()!='32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8':raise E('FACT-0109 child')
    branches=[{'il':f'0x{i:04X}','opcode':op,'target':f'0x{val:04X}'} for i,op,val in instructions if op in ('blt.un','bgt.un')]
    if digest(branches)!=BR_SHA:raise E('branch graph')
    expect=[('AIActFunc_GoFrontGrapple','0x06004FB0','0x000D',266,'fe0478463f631f1ff67e0445960fb13a4d4e7b436d2a261f50716bb116f6ba3f'),('AIActFunc_GoBackGrapple','0x06004FB1','0x0036',235,'05aa37f29b638f8da45743303251598eea9a5bf501388a75d7f0208ea0a2175c')]
    rr=references(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if len(rr)!=2 or digest(rr)!=REF_SHA:raise E('complete reference map')
    for got,(nm,tok,il,sz,sha) in zip(rr,expect):
        if (got['caller_method'],got['caller_token'],got['call_il'],got['caller_code_size'],got['caller_code_sha256'],got['opcode'])!=(nm,tok,il,sz,sha,'call'):raise E('caller metadata')
    cs=sorted({v['caller_token'] for v in rr})
    if hashlib.sha256(('\n'.join(cs)+'\n').encode()).hexdigest()!=CALLER_SHA:raise E('caller set')
    return {'code_size':126,'body_sha256':SHA,'methoddef_children':1,'memberref_method_calls':0,'direct_reference_count':2,'direct_caller_method_count':2}
def verify_r6(path):
    if base.sh(path)!=R6_SHA:raise E('R6 capture identity')
    wanted={n:0 for n in ['PlayerController_AI.GetGoAroundDir','PlayerMan.GetPlObj','PlayerController_AI.AIActFunc_GoFrontGrapple','PlayerController_AI.AIActFunc_GoBackGrapple']}
    with zipfile.ZipFile(path) as zz:
        if zz.testzip():raise E('R6 CRC')
        names=[n for n in zz.namelist() if Path(n).name=='event_trace.tsv']
        if len(names)!=1:raise E('R6 event member count')
        data=zz.read(names[0])
        if hashlib.sha256(data).hexdigest()!=EVENT_SHA:raise E('R6 trace identity')
        for row in csv.DictReader(io.StringIO(data.decode('utf-8-sig')),delimiter='\t'):
            if row['method'] in wanted:wanted[row['method']]+=1
    if any(wanted.values()):raise E('R6 boundary')
    return {'row_counts':wanted,'promoted_as_evidence':False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--r6',required=True);a=ap.parse_args()
    try:
        print(json.dumps({'dll':verify_dll(a.dll),'r6':verify_r6(a.r6)},sort_keys=True,indent=2))
        print('PROVE_PLAYERCONTROLLER_AI_GET_GO_AROUND_DIR: PASS');return 0
    except Exception as ex:
        print('PROVE_PLAYERCONTROLLER_AI_GET_GO_AROUND_DIR: FAIL',ex);return 1
if __name__=='__main__':raise SystemExit(main())
