#!/usr/bin/env python3
"""FACT-0348: independently verify original fpw panel byte equalities and prior retail-DLL offset witnesses.
This is read-only original evidence verification, not RS playback/emulation.
"""
import argparse,collections,hashlib,json,re,struct
from pathlib import Path
from prove_original_440_fpw_rs_panel import prove as verify_panel
R=Path(__file__).resolve().parents[1]
W=R/'canonical/witnesses/RESPANEL-001/original_440_fpw_first_record_byte_relations.summary.json'
P=R/'canonical/witnesses/RESPANEL-001/original_440_fpw_rs_panel.summary.json'
DLL_ENTRY=R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json'
DLL_16=R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_sixteen_anmnum_source_loop.summary.json'
DLL_ROUTE=R/'canonical/witnesses/CAP-R6-001/skill_data_man_load_rsf_file_resource_route.summary.json'
def ck(cond,msg):
    if not cond: raise AssertionError(msg)
def sha(buf):return hashlib.sha256(buf).hexdigest()
def prove(packed,report,metadata,ggm,w):
    full=json.loads(P.read_text(encoding='utf8'))
    old=verify_panel(packed,report,metadata,ggm,full)
    ck(old['object_count']==440 and old['original_packed_sha']=='PASS','prior original 440 source panel source proof')
    dll_entry=json.loads(DLL_ENTRY.read_text(encoding='utf8'))
    dll_16=json.loads(DLL_16.read_text(encoding='utf8'))
    dll_route=json.loads(DLL_ROUTE.read_text(encoding='utf8'))
    d=w['dll']
    for v in (dll_entry['dll'],dll_16['dll'],dll_route['dll']):
        ck(v['sha256']==d['original_sha256'],'matching original DLL file source SHA')
    ck(dll_entry['dll']['method']['code_sha256']==d['il_sha256'],'original parser IL SHA first entry')
    ck(dll_16['dll']['method']['code_sha256']==d['il_sha256'],'original parser IL SHA anm array')
    fields={f['name']:f['source'] for f in dll_entry['dll']['window']['fields'] if isinstance(f['source'],int)}
    for k,offset in [('formNum',64),('hitSE',69),('cheerLevel',70)]:
        ck(fields.get(k)==offset==d['parser_source_offsets']['first_entry_field_'+k],'original DLL first-entry field map '+k)
    ck(dll_16['dll']['window']['first_relative_input_byte']==48 and dll_16['dll']['window']['last_relative_input_byte']==63,'original DLL 16-array source range')
    ck(d['parser_source_offsets']['anm_num_source_array']==[48,63],'witness DLL byte-index map')
    ck(dll_entry['dll']['window']['source_array_argument']=='arg1','original source argument record')
    ck(dll_route['dll']['method']['code_sha256']==d['source_file_route_il_sha256'],'original source LoadRSFFile method identity')
    b=Path(packed).read_bytes();info=json.loads(Path(report).read_bytes())
    ck((len(b),sha(b))==(w['panel']['bytes'],w['panel']['sha256']),'original exact panel identity')
    ck(len(info['Entries'])==w['observed']['sample_count']==440,'original indexed source count')
    records=[];family=collections.defaultdict(list);len_values=[];seen=set();anchor_map={x['name']:x for x in w['anchors']}
    ck(len(anchor_map)==3,'immutable exemplar count')
    anchors_seen=set()
    for e in info['Entries']:
        body=b[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        n=struct.unpack_from('<I',body,0)[0]
        start=((4+n+3)&~3)+4
        data=body[start:-4]
        name=e['ResourceName'].split('/')[-1]
        ck(len(data)>=76,'minimum original source byte positions')
        ck(data[48]==data[64]+1,'raw byte48/64 equality '+name)
        ck(data[8:10]==data[69:71],'raw two-byte 8/69 equality '+name)
        ck(data[10:12]==data[72:74],'raw two-byte 10/72 equality '+name)
        ck((e['PathId'],name) not in seen,'original unique indexed named resource')
        seen.add((e['PathId'],name))
        row={'index':e['SourceIndex'],'name':name,'path_id':e['PathId'],'len':len(data),
          'v48':data[48],'v64':data[64],'b8':data[8],'b9':data[9],
          'b10':data[10],'b11':data[11],'b69':data[69],'b70':data[70],
          'b72':data[72],'b73':data[73]}
        records.append(row);len_values.append(len(data))
        mm=re.fullmatch(r'(fpw_[0-9]+)_([012])',name)
        if mm:family[mm.group(1)].append((int(mm.group(2)),len(data)))
        if name in anchor_map:
            a=anchor_map[name]
            ck((row['index'],row['path_id'],row['len'],row['v48'],row['v64'])==(a['index'],a['path_id'],a['embedded_bytes'],a['byte_48'],a['byte_64']),'source anchor header')
            for key,left in [('bytes_8_9',(8,9)),('bytes_69_70',(69,70)),('bytes_10_11',(10,11)),('bytes_72_73',(72,73))]:
                ck(a[key]==[data[z] for z in left],'source anchor '+key)
            anchors_seen.add(name)
    ck(anchors_seen==set(anchor_map),'all original source examples')
    obs=w['observed']
    ck((min(len_values),max(len_values))==(obs['min_embedded_bytes'],obs['max_embedded_bytes'])==(148,2488),'source embedded byte length extrema')
    ck(len(records)==obs['sample_count']==440,'complete original named panel')
    enc=json.dumps(records,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8')
    ck(sha(enc)==obs['normalized_440_byte_relation_index_sha256'],'complete original source byte relation index SHA')
    sizes=collections.Counter(len(g) for g in family.values())
    ck((len(family),sizes[2],sizes[3],sum(len(g) for g in family.values()),len(records)-sum(len(g) for g in family.values()))==
       (obs['variant_families'],obs['two_variant_families'],obs['three_variant_families'],obs['total_suffixed_objects'],obs['standalone_objects'])==
       (65,58,7,137,303),'exact original naming group histogram')
    ck(all(len({x[1] for x in group})==1 for group in family.values()),'group original byte length equality')
    ck(w['dataset_id']=='UNITY_FPW440_RSF_FIRST_RECORD_BYTE_RELATIONS_DLL_BRIDGE_V1','dataset label')
    return {'fact':'FACT-0348','source_panel_sha':'PASS','prior_full_source_prover':'PASS','existing_original_dll_witnesses':'PASS',
            'repeated_byte_relations':440,'variant_families':65,'actual_playback_tested':False,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for arg in ['packed','report','metadata-prefix','globalgamemanagers']:p.add_argument('--'+arg,required=True)
    a=p.parse_args()
    w=json.loads(W.read_text(encoding='utf8'))
    print(json.dumps(prove(a.packed,a.report,a.metadata_prefix,a.globalgamemanagers,w),sort_keys=True))
    print('FACT0348_440_SOURCE_AND_DLL_BYTE_OFFSET_BRIDGE_PASS')
