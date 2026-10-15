#!/usr/bin/env python3
"""FACT-0359: read-only original DLL, GGM container and resources metadata object join."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESMETA-001/original_fprform_rff_ggm_loader_join.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(v,m):
    if not v:raise AssertionError(m)
def prove(dll_path,ggm_path,metadata_path,w):
    d=Path(dll_path).read_bytes();g=Path(ggm_path).read_bytes();r=Path(metadata_path).read_bytes()
    a=w['original_dll'];q=w['original_ggm'];n=w['original_metadata_prefix']
    ck((len(d),sha(d))==(a['bytes'],a['sha256']),'original retail DLL exact file hash')
    ck((len(g),sha(g))==(q['bytes'],q['sha256']),'original GGM exact file hash')
    ck((len(r),sha(r))==(n['bytes'],n['sha256']),'original resources metadata exact prefix hash')
    ss,peoff=base.secs(d);st,hs,rows,pos=base.mdstreams(d,ss,peoff)
    sz,bl,ix,z,off=base.tables(d,st,hs,rows,pos)
    sb=st['#Strings'][0];bb=st['#Blob'][0]
    fm,owners=base.owner_maps(d,rows,sz,ix,z,off,sb)
    v=a['loader']
    md=base.method(d,ss,sz,bl,ix,z,off,sb,bb,owners,0x06001f0f)
    ck((md[0],md[1],md[4],md[7])==(v['methoddef_row_hex'],int(v['rva'],16),v['method'],(v['owner'],'')),'original loader MethodDef row, owner and RVA')
    ck(d[base.off(ss,md[1]):md[8]].hex()==v['method_header_hex'],'original loader method header')
    il=md[9]
    ck(len(il)==v['body_bytes']==83 and sha(il)==v['body_sha256'],'complete original loader IL identity')
    for window in v['windows']:
        ck(sha(il[window['start']:window['end']])==window['sha256'],'contiguous original IL window '+window['name'])
    ck([(k['start'],k['end']) for k in v['windows']]==[(0,32),(32,48),(48,67),(67,83)],'complete contiguous source coverage')
    literal=v['resource_name_user_string']
    ck(il[6]==0x72 and int.from_bytes(il[7:11],'little')==int(literal['token'],16),'original exact ldstr token')
    uspos=st['#US'][0]+literal['offset_in_user_string_heap']
    length=d[uspos]
    ck(length==literal['utf16le_data_length']==59,'original userstring source byte count')
    payload=d[uspos+1:uspos+1+length]
    ck(sha(payload)==literal['utf16le_data_sha256'] and payload[:-1].decode('utf-16-le')==literal['text'],'original DLL literal UTF16 source')
    instructions=v['instructions']
    ck(il[32]==0x20 and int.from_bytes(il[33:37],'little')==instructions['form_array_length_constant']==37999,'original array element count operand')
    ck(il[37]==0x8d and int.from_bytes(il[38:42],'little')==int(instructions['newarr_type_token'],16),'newarr original type token')
    ck(il[42]==0x7d and int.from_bytes(il[43:47],'little')==int(instructions['forms_field_token'],16),'stfld original Forms field token')
    ff=base.field(d,sz,bl,z,off,sb,bb,fm,0x040026dd)
    ck(ff[1]==('FormDataMan','') and ff[2]=='Forms','original Forms FieldDef owner/name')
    ck(il[55]==0x73 and int.from_bytes(il[56:60],'little')==int(instructions['parser_constructor_token'],16),'original parser parameter constructor')
    ck(il[60]==0x28 and int.from_bytes(il[61:65],'little')==int(instructions['parse_call_token'],16),'original parser call token')
    parser=base.method(d,ss,sz,bl,ix,z,off,sb,bb,owners,0x06001f12)
    ck(parser[4]=='ParseFormData_RFF' and parser[7]==('FormDataMan',''),'original parser MethodDef identity')
    rm=g[q['resource_manager_offset']:q['resource_manager_offset']+q['resource_manager_bytes']]
    count=struct.unpack_from('<I',rm,0)[0]
    ck(count==q['record_count']==43941,'original ResourceManager named source count')
    pos=4;target=q['entry'];found=None
    for i in range(count):
        start=pos
        ln=struct.unpack_from('<I',rm,pos)[0];pos+=4
        ck(ln<=2048 and pos+ln<=len(rm),'GGM source name bounds')
        name=rm[pos:pos+ln].decode('utf8')
        pos=(pos+ln+3)&~3
        fid,pid=struct.unpack_from('<iq',rm,pos);pos+=12
        if i==target['index']:
            found={'index':i,'resource_name':name,'file_id':fid,'path_id':pid,'record_relative_offset':start,'record_absolute_offset':start+q['resource_manager_offset'],'record_bytes':pos-start,'record_sha256':sha(rm[start:pos])}
            ck(found==target,'original complete GGM RFF row source')
    ck(pos==2138488 and found is not None,'complete GGM source name/reference sequence')
    ck(literal['text'].lower()==target['resource_name'],'literal source labels match only under ASCII lowercasing')
    pos=20;end=r.index(bytes((0,)),pos);ck(r[pos:end].decode()==n['unity_version'],'original Unity metadata version')
    pos=end+1;platform,tree,type_count=struct.unpack_from('<iBI',r,pos);pos+=9
    ck((platform,tree,type_count)==(5,0,455),'serialized original type descriptor header')
    classes=[]
    for _ in range(type_count):
        cid,deleted,script=struct.unpack_from('<iBh',r,pos)
        ck(deleted==0,'source serialized type status')
        pos+=39 if cid==114 else 23;classes.append(cid)
    object_count=struct.unpack_from('<I',r,pos)[0];pos=(pos+7)&~3
    ck(object_count==n['objectinfo_count']==90992,'original ObjectInfo count')
    found_obj=None
    for _ in range(object_count):
        start=pos;pid,rel,size,ti=struct.unpack_from('<qIII',r,pos);pos+=20
        if pid==n['object']['path_id']:
            found_obj={'path_id':pid,'objectinfo_row_offset':start,'objectinfo_row_sha256':sha(r[start:pos]),'class_id':classes[ti],'type_index':ti,'payload_relative_offset':rel,'payload_absolute_offset':n['data_offset']+rel,'declared_body_bytes':size}
    ck(found_obj==n['object'],'original metadata PathID22906 exact row/class/offset/size')
    ck(found['path_id']==found_obj['path_id']==22906,'original GGM PPtr to serialized ObjectInfo join')
    return {'fact':'FACT-0359','original_loader_il_sha256':sha(il),'ggm_entry':43500,'path_id':22906,'original_declared_body_bytes':12800024,'object_payload_examined':False,'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--dll',required=True);ap.add_argument('--globalgamemanagers',required=True);ap.add_argument('--metadata-prefix',required=True)
    args=ap.parse_args()
    print(json.dumps(prove(args.dll,args.globalgamemanagers,args.metadata_prefix,json.loads(W.read_text())),sort_keys=True))
    print('FACT0359_ORIGINAL_FPRFORM_RFF_LOADER_GGM_JOIN_PASS')
