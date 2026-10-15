#!/usr/bin/env python3
"""FACT-0349 source-only original 440 RS byte vector and original DLL input-window audit."""
import argparse,collections,hashlib,json,re,struct
from pathlib import Path
from prove_original_440_fpw_rs_panel import prove as prove_panel
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESPANEL-001/original_440_fpw_16_byte_vector_order.summary.json'
P=ROOT/'canonical/witnesses/RESPANEL-001/original_440_fpw_rs_panel.summary.json'
DLL=ROOT/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_sixteen_anmnum_source_loop.summary.json'
def digest(x):return hashlib.sha256(x).hexdigest()
def ensure(x,msg):
    if not x:raise AssertionError(msg)
def verify(packed,report,metadata,ggm,w):
    panel_w=json.loads(P.read_text(encoding='utf8'))
    old=prove_panel(packed,report,metadata,ggm,panel_w)
    ensure(old['fact']=='FACT-0347' and old['object_count']==440 and old['original_packed_sha']=='PASS','existing original 440-source provenance')
    prior=json.loads(DLL.read_text(encoding='utf8'))['dll']
    method=prior['method'];win=prior['window'];d=w['original_dll'];o=w['observed'];p=w['original_panel']
    ensure(prior['sha256']==d['sha256'] and method['code_sha256']==d['full_il_sha256'],'matching original retail DLL source identity')
    ensure(method['token']==d['original_methoddef']=='0x0600525F','matching original retail parser MethodDef')
    ensure(win['source_sha256']==d['IL_read_window_sha256'],'original 57-byte IL window SHA')
    ensure((win['first_relative_input_byte'],win['last_relative_input_byte'],win['array_length'])==(48,63,16),'original source byte array read indices')
    ensure(win['target_method']['methoddef_token']==d['original_16_array_target'].split(' ')[-1]=='0x06005265','original GetAnmNum call')
    ensure(win['destination_field']['fielddef_token']==d['original_result_field'].split(' ')[-1]=='0x04007C54','original SkillData.anmNum store')
    raw=Path(packed).read_bytes();rbytes=Path(report).read_bytes()
    ensure((len(raw),digest(raw))==(p['bytes'],p['sha256']),'original panel SHA')
    ensure(digest(rbytes)==p['report_sha256'],'original panel report SHA')
    reportj=json.loads(rbytes);entries=reportj['Entries']
    ensure(len(entries)==o['source_objects']==440,'complete original named resource list')
    family=collections.defaultdict(list);rows=[];vectors=[]
    constant=0;increases=0;tail=0;nondecreasing=0;v64=0
    names_seen=set();anchors={x['name']:x for x in w['anchors']};anchors_verified=set()
    for e in entries:
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        n=struct.unpack_from('<I',body,0)[0];start=((4+n+3)&~3)+4
        dbytes=body[start:-4]
        name=e['ResourceName'].split('/')[-1]
        ensure(name not in names_seen,'unique original filename');names_seen.add(name)
        ensure(len(dbytes)>=65,'byte window source bounds')
        vec=list(dbytes[48:64]);ensure(len(vec)==16,'original 16-byte span')
        rows.append({'index':e['SourceIndex'],'path_id':e['PathId'],'name':name,'len':len(dbytes),'vec':vec,'v64':dbytes[64]})
        vectors.append(bytes(vec))
        nd=all(a<=b for a,b in zip(vec,vec[1:]))
        ensure(nd,'source sequence not nondecreasing: '+name)
        nondecreasing+=1
        if len(set(vec))==1:constant+=1
        else:increases+=1
        if len(set(vec[9:]))==1:tail+=1
        if vec[0]==dbytes[64]+1:v64+=1
        mt=re.fullmatch(r'(fpw_\d+)_([012])',name)
        if mt:family[mt.group(1)].append((mt.group(2),len(dbytes),tuple(vec)))
        if name in anchors:
            a=anchors[name]
            ensure((e['SourceIndex'],e['PathId'],len(dbytes),vec,dbytes[64])==(a['index'],a['path_id'],a['embedded_bytes'],a['vector'],a['source_byte64']),'exact original source exemplar')
            anchors_verified.add(name)
    ensure(anchors_verified==set(anchors) and len(anchors)==3,'all three prior source anchors')
    ensure((nondecreasing,constant,increases,tail,v64)==
        (o['full_16_byte_vectors_non_decreasing'],o['full_16_byte_vectors_constant'],o['full_16_byte_vectors_some_increase'],o['byte_offsets_57_to_63_constant_within_each_vector'],o['first_source_byte_equals_source_byte64_plus_one_count'])==
        (440,55,385,440,440),'complete 440 vector properties')
    ensure(len(set(vectors))==o['distinct_16_byte_vectors']==273,'unique 16-source-byte vector count')
    ensure(digest(b''.join(vectors))==o['original_vec48_63_concatenated_sha256'],'all 7040 original source-byte SHA')
    ensure(digest(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['indexed_440_vec_rows_sha256'],'indexed 440 source witness SHA')
    ensure(min(r['vec'][0] for r in rows)==o['min_vec_first'] and max(r['vec'][0] for r in rows)==o['max_vec_first'],'first original byte extrema')
    ensure(min(max(r['vec']) for r in rows)==o['min_vec_maximum'] and max(max(r['vec']) for r in rows)==o['max_vec_maximum'],'last original byte extrema')
    nums=collections.Counter(len(x) for x in family.values())
    ensure((len(family),nums[2],nums[3],sum(map(len,family.values())))==(65,58,7,137),'source variant family size counts')
    ensure(all(len({x[1] for x in grp})==1 and len({x[2] for x in grp})==1 for grp in family.values()),'every family shared embedded length and 16 bytes')
    ensure(o['all_65_families_have_identical_16_byte_vectors'] is True and o['all_65_families_have_equal_embedded_source_length'] is True,'source witness classification')
    ensure(w['dataset_id']=='UNITY_FPW440_RSF_16_SOURCE_BYTE_VECTOR_ORDER_AND_VARIANT_IDENTITY_V1','witness identity')
    return {'fact':'FACT-0349','original_440_source_proven':True,'original_dll_instruction_witness_proven':True,
            'nondecreasing_16_byte_vectors':nondecreasing,'constant_vectors':constant,'variants':sum(map(len,family.values())),
            'actual_animation_timing_claim':False,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for arg in ['packed','report','metadata-prefix','globalgamemanagers']:p.add_argument('--'+arg,required=True)
    a=p.parse_args()
    print(json.dumps(verify(a.packed,a.report,a.metadata_prefix,a.globalgamemanagers,json.loads(W.read_text(encoding='utf8'))),sort_keys=True))
    print('FACT0349_ORIGINAL_440_RSF_16BYTE_ORDER_PASS')
