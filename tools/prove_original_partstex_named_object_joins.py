#!/usr/bin/env python3
"""FACT-0369 original-source PartsTex name/PPtr to Unity ObjectInfo joins.
Read-only: verify SHA-pinned original two files without Unity execution.
"""
import argparse,collections,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESMETA-001/original_partstex_named_texture_sprite_object_joins.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(v,msg):
    if not v:raise AssertionError(msg)
def prove(ggm_path,meta_path,s):
    g=Path(ggm_path).read_bytes();m=Path(meta_path).read_bytes()
    a=s['original_globalgamemanagers'];b=s['original_resources_metadata'];e=s['partstex']
    ck((len(g),sha(g))==(a['bytes'],a['sha256']),'full original GGM SHA')
    ck((len(m),sha(m))==(b['bytes'],b['sha256']),'original metadata prefix SHA')
    ck(struct.unpack_from('>IIIII',m,0)==(1842202,3166587532,17,1842224,0),'Unity source header')
    p=20;q=m.index(0,p);ck(m[p:q]==b'5.6.5p3','Unity version');p=q+1
    platform,tree,count=struct.unpack_from('<iBI',m,p);p+=9
    ck((platform,tree,count)==(5,0,b['type_count']),'original type header')
    types=[]
    for _ in range(count):
        cls,st,script=struct.unpack_from('<iBh',m,p);p+=7
        ck(st==0,'original type stripped flag')
        if cls==114:p+=16
        p+=16;types.append(cls)
    ck(p==17206,'type table bounds')
    count=struct.unpack_from('<I',m,p)[0];p=(p+3)&~3
    ck((count,p)==(b['object_count'],b['object_table_begin']),'original object header')
    end=p+20*count
    ck(end==b['object_table_end'] and sha(m[p:end])==b['object_table_sha256'],'source ObjectInfo SHA')
    obj={}
    for i in range(count):
        pid,offset,size,typ=struct.unpack_from('<qIII',m,p+20*i)
        ck(pid==i+1 and size>0 and 0<=typ<len(types),'original indexed ObjectInfo')
        obj[pid]=(types[typ],offset,size)
    ck(sum(cls==28 for cls,off,sz in obj.values())==19625,'original total Texture2D objects')
    ck(sum(cls==213 for cls,off,sz in obj.values())==19628,'original total Sprite objects')
    off=a['resource_manager_absolute_offset'];d=g[off:off+a['resource_manager_bytes']]
    ck(sha(d)==a['resource_manager_sha256'],'original resource manager body SHA')
    n=struct.unpack_from('<I',d)[0];ck(n==a['container_count'],'original source name/PPtr count')
    p=4;rows=[]
    for i in range(n):
        size=struct.unpack_from('<I',d,p)[0];p+=4
        ck(size<=2048 and p+size<=len(d),'original source name size')
        name=d[p:p+size].decode('utf8');p=(p+size+3)&~3
        fid,pid=struct.unpack_from('<iq',d,p);p+=12
        if name.startswith(e['name_prefix']):
            ck(fid==e['file_id'] and pid in obj,'original named resource pointer')
            cls,rel,sz=obj[pid]
            ck(cls in (28,213),'original named Partstex source class')
            rows.append(dict(index=i,name=name,file_id=fid,path_id=pid,class_id=cls,relative_offset=rel,byte_size=sz))
    ck(p==a['container_source_end_offset'],'original ResourceManager table end')
    ck(len(rows)==e['source_named_references'],'source named links count')
    names=collections.defaultdict(list);folders=collections.defaultdict(collections.Counter)
    for row in rows:
        names[row['name']].append(row)
        folders[row['name'].split('/')[1]][row['class_id']]+=1
    ck(len(names)==e['distinct_names'],'original named asset count')
    ck(sum(row['class_id']==28 for row in rows)==e['texture2d_refs'],'original class28 links')
    ck(sum(row['class_id']==213 for row in rows)==e['sprite_refs'],'original class213 links')
    ck(sum(len(v)==2 and {r['class_id'] for r in v}=={28,213} for v in names.values())==e['dual_class_names'],'original Texture2D/Sprite name pairs')
    single=sorted(n for n,v in names.items() if len(v)==1 and v[0]['class_id']==28)
    ck(single==e['texture2d_only_exact_names'] and len(single)==e['texture2d_only_names'],'original seven texture-only names')
    ck(all(len(v) in (1,2) for v in names.values()),'no third class/name')
    counted=[dict(folder=name,texture2d_count=c[28],sprite_count=c[213]) for name,c in sorted(folders.items())]
    ck(counted==e['folder_counts'],'original complete eleven-folder counts')
    serialized=json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8')
    ck(sha(serialized)==e['normalized_join_sha256'],'entire original named join digest')
    return dict(fact='FACT-0369',named_references=len(rows),names=len(names),texture2d=e['texture2d_refs'],sprites=e['sprite_refs'],texture_only=len(single),runtime_eligible=False)
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--globalgamemanagers',required=True);p.add_argument('--resources-metadata-prefix',required=True)
    args=p.parse_args()
    s=json.loads(W.read_text())
    print(json.dumps(prove(args.globalgamemanagers,args.resources_metadata_prefix,s),sort_keys=True))
    print('FACT0369_ORIGINAL_PARTSTEX_NAMED_OBJECT_JOIN_PASS')
