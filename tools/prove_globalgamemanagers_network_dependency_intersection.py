#!/usr/bin/env python3
"""FACT-0342 exact original-byte ClassID149/ResourceManager cross-index witness."""
import argparse,hashlib,json,struct
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/GGM-001/network_590_dependency_intersection.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(ok,reason):
    if not ok:raise AssertionError(reason)
def prove(path,w):
    b=Path(path).read_bytes();src=w['original_file']
    ck(len(b)==src['bytes'] and sha(b)==src['sha256'],'original entire file identity')
    o=w['source_objects'];res=o['resource_manager'];network=o['class149']
    rm=b[res['offset']:res['offset']+res['bytes']]
    nm=b[network['offset']:network['offset']+network['bytes']]
    ck(sha(rm)==res['sha256'] and sha(nm)==network['sha256'],'two original ObjectInfo body hashes')
    ck(len(rm)==res['bytes']==4862328 and len(nm)==network['bytes']==16532,'ObjectInfo bounds')
    names={};p=4
    ck(struct.unpack_from('<I',rm,0)[0]==res['name_index_records']==43941,'FACT0338 name count')
    for _ in range(43941):
        n=struct.unpack_from('<I',rm,p)[0];p+=4
        ck(n<=2048 and p+n<=res['name_index_bytes'],'original name bounds')
        name=rm[p:p+n].decode('utf-8');end=p+n;p=(end+3)&~3
        ck(rm[end:p]==bytes(p-end),'original name padding')
        pair=struct.unpack_from('<iq',rm,p);p+=12
        names[pair]=name
    ck(p==res['name_index_bytes'] and len(names)==43941,'FACT0338 complete name index')
    dep=rm[p:];ck(len(dep)==res['dependency_region_bytes'] and sha(dep)==res['dependency_region_sha256'],'FACT0339 original dependency region')
    ck(struct.unpack_from('<I',dep,0)[0]==res['dependency_records']==65218,'FACT0339 record count')
    parents={};incoming=Counter();pos=4
    for i in range(65218):
        ck(pos+16<=len(dep),'parent bound')
        fid,pid,arity=struct.unpack_from('<iqI',dep,pos);pos+=16
        ck(1<=fid<=5 and pid>0 and 1<=arity<=168 and pos+12*arity<=len(dep),'parent and array bounds')
        children=[struct.unpack_from('<iq',dep,pos+j*12) for j in range(arity)]
        pos+=12*arity;parents[(fid,pid)]=(arity,children)
        incoming.update(children)
    ck(pos==len(dep) and len(parents)==65218,'dependency original source exhausted')
    j=w['join'];counts=Counter();byboth=Counter();byneither=Counter();hist=Counter();categories=Counter()
    outbound=0;inbound=0;out_named=0;in_named=0
    identifiers=set();pairs=set()
    anchors={x['index']:x for x in j['anchors']}
    ck(struct.unpack_from('<I',nm,8)[0]==network['rows']==590,'original 590-row count')
    ck(12+590*28==len(nm),'complete ClassID149 source')
    for index in range(590):
        off=12+28*index
        identifier=nm[off:off+16];pair=struct.unpack_from('<iq',nm,off+16)
        ck(any(identifier) and pair[0]>0 and pair[1]>0,'original valid reference')
        identifiers.add(identifier);pairs.add(pair)
        parent=pair in parents;child=pair in incoming
        relation='both' if parent and child else 'parent_only' if parent else 'child_only' if child else 'neither'
        name=names.get(pair);counts[relation]+=1
        counts[('named_' if name is not None else 'unnamed_')+relation]+=1
        out=parents[pair][0] if parent else 0;inc=incoming[pair]
        outbound+=out;inbound+=inc
        if parent:hist[str(out)]+=1;byboth[str(pair[0])]+=1
        else:byneither[str(pair[0])]+=1
        if name is not None:
            out_named+=out;in_named+=inc
            if parent:categories[name.split('/')[0]]+=1
        if index in anchors:
            a=anchors[index];first=[list(c) for c in parents[pair][1][:3]] if parent else []
            ck((identifier.hex(),pair[0],pair[1],name,relation,out,inc,first)==
               (a['id_hex'],a['file_id'],a['path_id'],a['resource_name'],a['relation'],a['outgoing_count'],a['incoming_occurrences'],a['first_outgoing']),
               'indexed original cross-object source anchor '+str(index))
    ck(len(identifiers)==j['unique_class149_identifiers']==590,'unique identifiers')
    ck(len(pairs)==j['unique_class149_numeric_references']==590,'unique numeric refs')
    expected={'both':j['both_parent_and_child'],'parent_only':j['parent_only'],'child_only':j['child_only'],'neither':j['neither'],
              'named_both':j['both_with_resource_name'],'unnamed_both':j['both_without_resource_name'],
              'named_neither':j['neither_with_resource_name'],'unnamed_neither':j['neither_without_resource_name']}
    ck(all(counts[k]==v for k,v in expected.items()),'all four exact parent/child relation counts')
    ck(dict(byboth)==j['both_by_file_id'] and dict(byneither)==j['neither_by_file_id'],'fileID relation distribution')
    ck(dict(hist)==j['outgoing_arity_counts'] and dict(categories)==j['both_named_categories'],'arity/name category counts')
    ck((outbound,inbound,out_named,in_named)==(j['total_outgoing_occurrences_for_joined_parents'],j['total_incoming_occurrences_for_joined_references'],j['named_parent_outgoing_occurrences'],j['named_reference_incoming_occurrences']),'dependency occurrence sums')
    return {'fact':'FACT-0342','source_sha':'PASS','network_refs':590,'both_sides':counts['both'],'neither_side':counts['neither'],'outbound_edges':outbound,'incoming_occurrences':inbound,'runtime_unlocked':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--globalgamemanagers',required=True);args=ap.parse_args()
    w=json.loads(W.read_text(encoding='utf-8'));print(json.dumps(prove(args.globalgamemanagers,w),sort_keys=True));print('FACT0342_SOURCE_INTERSECTION_PASS')
