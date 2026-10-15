#!/usr/bin/env python3
"""FACT-0344: exact original resources.assets metadata prefix and GGM-001 PPtr joins.

Read-only input is ONLY the original metadata prefix, not the resource object bodies.
"""
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
WITNESS = ROOT/'canonical/witnesses/RESMETA-001/original_90992_objectinfo_43930_ggm_joins.summary.json'
def sha(buf):
    return hashlib.sha256(buf).hexdigest()
def check(predicate, label):
    if not predicate:
        raise AssertionError(label)
def prove(prefix_path, ggm_path, witness):
    raw = Path(prefix_path).read_bytes()
    ggm = Path(ggm_path).read_bytes()
    src = witness['metadata_prefix']
    gs = witness['original_ggm']
    check((len(raw), sha(raw)) == (src['bytes'], src['sha256']), 'original prefix exact SHA')
    check((len(ggm), sha(ggm)) == (gs['bytes'], gs['sha256']), 'original GGM exact SHA')
    check(struct.unpack_from('>IIIII',raw,0) == (1842202,3166587532,17,1842224,0), 'original Unity header')
    pos=20
    end=raw.index(b'\0',pos)
    check(raw[pos:end]==b'5.6.5p3','original Unity version')
    pos=end+1
    platform, tree, count=struct.unpack_from('<iBI',raw,pos)
    pos+=9
    types=witness['types']
    check((platform,tree,count,pos)==(5,0,455,types['table_start']),'original 455 type rows')
    classes=[]
    type_counts=collections.Counter()
    for _ in range(count):
        class_id,deleted,_script=struct.unpack_from('<iBh',raw,pos)
        check(deleted==0,'serialized type record')
        pos+=39 if class_id==114 else 23
        check(pos<=types['table_end'],'type row bounds')
        classes.append(class_id)
        type_counts[str(class_id)]+=1
    check(pos==types['table_end'] and sha(raw[types['table_start']:pos])==types['table_sha256'], 'complete original type table SHA')
    check(len(type_counts)==types['unique_class_ids'] and type_counts['114']==types['class_id114_type_entries'], 'type count breakdown')
    check(dict(type_counts)==types['class_id_type_record_counts'],'type class histogram')
    info=witness['objectinfo']
    object_count=struct.unpack_from('<I',raw,pos)[0]
    pos=(pos+4+3)&~3
    check((object_count,pos)==(info['count'],info['table_start']), 'original ObjectInfo count/start')
    objects={}
    class_counts=collections.Counter()
    gaps=collections.Counter()
    prev=0
    body_sum=0
    for i in range(object_count):
        start=pos
        pid,relative,size,ti=struct.unpack_from('<qIII',raw,pos)
        pos+=20
        check(pid==i+1 and 0<=ti<len(classes) and size>0 and relative>=prev,'ordered object record')
        check(src['data_offset']+relative+size<=src['original_file_bytes_declared'],'object declared physical bounds')
        if relative>prev:
            gaps[str(relative-prev)]+=1
        prev=relative+size
        body_sum+=size
        klass=classes[ti]
        class_counts[str(klass)]+=1
        objects[pid]=(ti,klass,relative,size,sha(raw[start:pos]))
    check(pos==info['table_end'] and sha(raw[info['table_start']:pos])==info['table_sha256'],'original 90992-row ObjectInfo SHA')
    check(len(objects)==info['unique_path_ids']==90992,'original unique PathIDs')
    check(prev==info['declared_payload_relative_end']==src['original_file_bytes_declared']-src['data_offset'],'last original declared object end')
    check(body_sum==info['declared_body_bytes_sum'],'declared body sizes sum')
    check(sum(int(k)*v for k,v in gaps.items())==info['declared_gap_bytes_sum'],'declared gap lengths sum')
    check(sum(gaps.values())==info['declared_gap_windows_sum'],'declared gap region count')
    check(dict(gaps)==info['declared_gap_length_counts'] and dict(class_counts)==info['class_id_object_counts'],'all declared gap and object-class histograms')
    scripts=witness['script_refs']
    start=pos
    n=struct.unpack_from('<I',raw,pos)[0]
    pos+=4
    check((n,start)==(scripts['count'],scripts['table_start']),'414 script PPtr table count')
    rows=[]
    for _ in range(n):
        rows.append(struct.unpack_from('<iq',raw,pos))
        pos+=12
    check(pos==scripts['table_end'] and sha(raw[start:pos])==scripts['table_sha256'],'414 script refs exact source')
    check(len(set(rows))==scripts['unique_pairs'] and list(rows[0])==scripts['first_pair'] and list(rows[-1])==scripts['last_pair'],'original script PPtr uniqueness and anchors')
    check({str(k):v for k,v in collections.Counter(x[0] for x in rows).items()}==scripts['file_id_counts'],'script reference file IDs')
    externals=witness['externals']
    start=pos
    n=struct.unpack_from('<I',raw,pos)[0]
    pos+=4
    check(n==externals['count'] and start==externals['table_start'],'external reference count')
    found=[]
    for i in range(n):
        rowstart=pos
        end=raw.index(b'\0',pos)
        asset=raw[pos:end].decode('utf-8')
        pos=end+1
        guid=raw[pos:pos+16].hex()
        pos+=16
        kind=struct.unpack_from('<i',raw,pos)[0]
        pos+=4
        end=raw.index(b'\0',pos)
        path=raw[pos:end].decode('utf-8')
        pos=end+1
        found.append(dict(file_id=i+1,start=rowstart,end=pos,asset_path=asset,guid_hex=guid,type=kind,path=path))
    check(found==externals['entries'],'four original dependency records')
    check(pos+1==externals['table_end']==len(raw) and raw[pos]==0,'original metadata terminal')
    check(sha(raw[start:])==externals['table_sha256'],'exact external record SHA')
    check(src['data_offset']-len(raw)==src['metadata_prefix_excludes_data_offset_gap_bytes']==2,'unsupplied alignment interval correctly excluded')
    joins=witness['ggm_join']
    rm=ggm[gs['resource_manager_absolute_start']:gs['resource_manager_absolute_start']+gs['resource_manager_bytes']]
    count=struct.unpack_from('<I',rm,0)[0]
    check(count==gs['resource_name_records'],'original ResourceManager record count')
    pos=4
    joined=0
    distinct=set()
    categories=collections.Counter()
    targetclasses=collections.Counter()
    anchors={x['index']:x for x in joins['anchors']}
    observed=set()
    for index in range(count):
        n=struct.unpack_from('<I',rm,pos)[0]
        pos+=4
        check(n<=2048 and pos+n<=len(rm),'GGM original source name bounds')
        name=rm[pos:pos+n].decode('utf-8')
        end=pos+n
        pos=(end+3)&~3
        check(rm[end:pos]==bytes(pos-end),'GGM name alignment')
        fid,pid=struct.unpack_from('<iq',rm,pos)
        pos+=12
        if fid==joins['ggm_file_id']:
            check(pid in objects,'GGM reference resolves to original metadata PathID')
            ti,klass,relative,size,row_sha=objects[pid]
            joined+=1
            distinct.add(pid)
            categories[name.split('/')[0]]+=1
            targetclasses[str(klass)]+=1
            if index in anchors:
                record=dict(index=index,name=name,file_id=fid,path_id=pid,type_index=ti,class_id=klass,relative_offset=relative,byte_size=size,objectinfo_row_sha256=row_sha)
                check(record==anchors[index],'indexed direct original GGM/object source anchor')
                observed.add(index)
    check(pos==2138488,'GGM original complete name source')
    check(joined==joins['named_reference_count']==joins['resolved_in_metadata_count']==43930,'all GGM fileID5 refs')
    check(len(distinct)==joins['unique_target_path_ids']==43930 and joins['unresolved_count']==0,'all 43930 unique and resolved')
    check(dict(categories)==joins['reference_category_counts'],'original GGM namespace histogram')
    check(dict(targetclasses)==joins['target_class_id_counts'],'original joined ClassID histogram')
    check(observed==set(anchors),'all source indexed anchors')
    check(witness['dataset_id']=='UNITY_RESOURCES_METADATA_90992_OBJECTINFO_43930_GGM_LINKS_V1','dataset identity')
    return {'fact':'FACT-0344','original_prefix_sha':'PASS','original_ggm_sha':'PASS',
            'objectinfo_records':90992,'named_target_joins':43930,
            'object_bodies_examined':False,'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--metadata-prefix',required=True)
    ap.add_argument('--globalgamemanagers',required=True)
    a=ap.parse_args()
    witness=json.loads(WITNESS.read_text(encoding='utf-8'))
    print(json.dumps(prove(a.metadata_prefix,a.globalgamemanagers,witness),sort_keys=True))
    print('FACT0344_SOURCE_METADATA_AND_GGM_JOINS_PASS')
