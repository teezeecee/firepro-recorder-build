#!/usr/bin/env python3
"""FACT-0340 original Unity ClassID149 590-record byte proof. Offline read-only.

Reconstructs original metadata from the user's own exact file; does not
include or modify retail game binaries and does not infer network activity.
"""
import argparse, hashlib, json, struct
from collections import Counter
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/'canonical/witnesses/GGM-001/network_manager_590_refs.summary.json'
def sha(x):return hashlib.sha256(x).hexdigest()
def ck(b,message):
    if not b:raise AssertionError(message)
def prove(path,w):
    source=Path(path).read_bytes();s=w['original_file'];obj=w['object'];t=w['record_table']
    ck((len(source),sha(source))==(s['bytes'],s['sha256']),'whole original source SHA256')
    ck(struct.unpack_from('>IIIII',source,0)==(1379,len(source),17,4096,0),'original Unity serialized header')
    p=20;q=source.index(bytes([0]),p)
    ck(source[p:q]==b'5.6.5p3','original Unity version');p=q+1
    platform,has_tree,type_count=struct.unpack_from('<iBI',source,p);p+=9
    ck((platform,has_tree,type_count)==(5,0,20),'original type table fields')
    class_ids=[]
    for _ in range(type_count):
        cid,deleted,script=struct.unpack_from('<iBh',source,p);p+=23
        ck((deleted,script)==(0,-1),'type-row metadata')
        class_ids.append(cid)
    cnt=struct.unpack_from('<I',source,p)[0];p=(p+7)&~7
    ck(cnt==20 and class_ids[obj['type_index']]==obj['class_id']==149,'original class ID and ObjectInfo count')
    objects={}
    for _ in range(cnt):
        pid,relative,size,ti=struct.unpack_from('<qIII',source,p);p+=20
        ck(ti<len(class_ids) and 4096+relative+size<=len(source),'ObjectInfo bound')
        objects[pid]=(relative,size,ti)
    ck(objects[obj['path_id']]==(obj['relative_offset'],obj['bytes'],obj['type_index']),'original ClassID149 ObjectInfo')
    start=4096+obj['relative_offset']
    ck(start==obj['absolute_offset'],'absolute object source offset')
    data=source[start:start+obj['bytes']]
    ck((len(data),sha(data))==(16532,obj['sha256']),'whole original object SHA')
    ck(list(struct.unpack_from('<III',data,0))==t['header_u32_words'],'header bit-exact words')
    ck(struct.unpack_from('<f',data,4)[0]==t['f32_at_object_offset_4_representation']==15.0,'float representation')
    ck(sha(data[:12])==t['header_sha256'] and sha(data[12:])==t['records_sha256'],'raw block hashes')
    ck(t['record_count']==590 and 12+590*t['record_bytes_each']==len(data),'record count and full source exhaustion')
    # Independent full FACT-0338 original name index read, not a hard-coded subset.
    r=source[0x1DFC8:0x1DFC8+4862328]
    ck(sha(r)=='414f1fba01d63bf13a63d82d9b7dbb7fd6223616deb4a57cb3a2ac1f8cbaf9de','FACT-0338 whole source bytes')
    pos=4;named={}
    ck(struct.unpack_from('<I',r,0)[0]==43941,'original ResourceManager name count')
    for _ in range(43941):
        size=struct.unpack_from('<I',r,pos)[0];pos+=4
        ck(size<=2048 and pos+size<=2138488,'original name bounds')
        name=r[pos:pos+size].decode('utf8');ending=pos+size;pos=(ending+3)&~3
        ck(r[ending:pos]==bytes(pos-ending),'name padding')
        fid,pid=struct.unpack_from('<iq',r,pos);pos+=12
        named[(fid,pid)]=name
    ck(pos==2138488 and len(named)==43941,'all source names and IDs')
    fid_counts=Counter();cats=Counter();missing=Counter();seen_identifiers=set();seen_pointers=set();matches=0
    anchors={item['index']:item for item in t['anchors']}
    for i in range(590):
        offset=12+28*i
        identifier=data[offset:offset+16]
        fid,pid=struct.unpack_from('<iq',data,offset+16)
        ck(any(identifier) and fid>0 and pid>0,'source numeric identifier and pointer')
        seen_identifiers.add(identifier);seen_pointers.add((fid,pid));fid_counts[str(fid)]+=1
        name=named.get((fid,pid))
        if name is None:missing[str(fid)]+=1
        else:matches+=1;cats[name.split('/')[0]]+=1
        if i in anchors:
            a=anchors[i]
            ck((identifier.hex(),fid,pid,name)==(a['identifier_hex'],a['file_id'],a['path_id'],a['resource_name']),
               'source anchor index '+str(i))
    ck(len(seen_identifiers)==t['unique_identifiers']==590,'identifier uniqueness')
    ck(len(seen_pointers)==t['unique_numeric_references']==590,'pointer uniqueness')
    ck(dict(fid_counts)==t['fileid_counts'],'exact source fileID distribution')
    ck(dict(cats)==t['matched_categories'],'exact named category joins')
    ck(matches==t['joined_fact0338_named_references']==534,'exact named joins')
    ck(sum(missing.values())==t['unmatched_named_index_references']==56,'unmatched reference count')
    ck(dict(missing)==t['unmatched_fileid_counts'],'unmatched fileID counts')
    ck(source[obj['end_absolute_offset']:obj['end_absolute_offset']+4].hex()==w['outside_object_following_padding']['hex'],
       'non-object alignment bytes')
    return {'fact':'FACT-0340','raw_source_pass':True,'source_records':590,'named_reference_joins':534,
            'no_unclassified_object_bytes':True,'retail_runtime_unlocked':False}
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--globalgamemanagers',required=True)
    args=a.parse_args()
    w=json.loads(W.read_text(encoding='utf8'))
    ck(w['dataset_id']=='UNITY_GGM_NETWORK_MANAGER_590_REFERENCE_RECORDS_V1','witness family ID')
    print(json.dumps(prove(args.globalgamemanagers,w),sort_keys=True))
    print('FACT-0340 original Unity source: PASS')
