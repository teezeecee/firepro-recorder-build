#!/usr/bin/env python3
"""Read-only exact original-byte SA0-001 plus GGM-001 structural prover."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/SA0-001/original_237_objects_11_ggm_joins.summary.json'
def digest(b): return hashlib.sha256(b).hexdigest()
def ck(condition,label):
    if not condition: raise AssertionError(label)
def prove(sa_path,ggm_path,w):
    a=Path(sa_path).read_bytes();g=Path(ggm_path).read_bytes()
    sa=w['original_files']['sharedassets0'];ggm=w['original_files']['globalgamemanagers']
    ck((len(a),digest(a))==(sa['bytes'],sa['sha256']),'full original SA0 SHA/length')
    ck((len(g),digest(g))==(ggm['bytes'],ggm['sha256']),'full original GGM SHA/length')
    ck(struct.unpack_from('>IIIII',a,0)==(6028,len(a),17,6048,0),'original Unity header')
    z=a.index(b'\0',20);ck(a[20:z]==b'5.6.5p3','Unity 5.6.5p3')
    platform,type_tree,type_count=struct.unpack_from('<iBI',a,z+1)
    ck((platform,type_tree,type_count)==(5,0,31),'Unity platform/tree/type count')
    m=w['metadata'];d=w['payload'];pos=z+10;ck(pos==37,'type start')
    classes=[];types=collections.Counter()
    for i in range(type_count):
        class_id,deleted,script_type=struct.unpack_from('<iBh',a,pos)
        ck(deleted==0 and (class_id==114 or script_type==-1),'original type record')
        row_bytes=39 if class_id==114 else 23
        ck(pos+row_bytes<=m['type_table_end'],'type row bounds')
        classes.append(class_id);types[class_id]+=1;pos+=row_bytes
    ck(classes==m['class_id_order'] and pos==974,'31 type records')
    ck(digest(a[37:974])==m['type_table_sha256'],'raw serialized types SHA')
    count=struct.unpack_from('<I',a,pos)[0];pos=(pos+4+3)&~3
    ck(count==237 and pos==980,'237 object metadata table')
    objects={};hist=collections.Counter();body_chunks=[];gap_chunks=[];gap_hist=collections.Counter()
    prior=6048
    for i in range(count):
        pid,relative,size,ti=struct.unpack_from('<qIII',a,pos);pos+=20
        ck(pid==i+1 and ti<len(classes),'source object ID/type bounds')
        absolute=6048+relative
        ck(absolute>=prior and absolute+size<=len(a) and size>0,'source object windows nonempty ordered')
        gap=a[prior:absolute]
        ck(all(x==0 for x in gap),'original gap zero bytes')
        if gap: gap_chunks.append(gap);gap_hist[str(len(gap))]+=1
        body=a[absolute:absolute+size]
        objects[pid]=(classes[ti],size,digest(body))
        hist[str(classes[ti])]+=1;body_chunks.append(body);prior=absolute+size
    ck(pos==5720 and digest(a[980:5720])==m['objectinfo_sha256'],'original ObjectInfo table SHA')
    ck(digest(a[20:6048])==m['sha256'] and digest(a[5720:6048])==m['metadata_tail_sha256'],'metadata SHA')
    ck(prior==len(a) and len(objects)==237,'end exact/unique object records')
    ck(sum(len(x) for x in body_chunks)==d['object_body_bytes'],'body byte sum')
    ck(sum(len(x) for x in gap_chunks)==d['gap_bytes'] and len(gap_chunks)==d['gap_count'],'original gap lengths')
    ck(dict(gap_hist)==d['gap_length_histogram'] and dict(hist)==d['class_id_counts'],'original gap/class counts')
    ck(digest(a[6048:])==d['sha256'],'original whole payload SHA')
    ck(digest(b''.join(body_chunks))==d['object_bodies_in_order_sha256'],'all 237 bodies aggregate')
    ck(digest(b''.join(gap_chunks))==d['gap_bytes_in_order_sha256'],'all 130 alignment bytes aggregate')
    ck(d['object_body_bytes']+d['gap_bytes']==d['bytes']==len(a)-6048,'complete original payload')
    rm=w['ggm_join'];buf=g[rm['resource_manager_object_absolute_start']:rm['resource_manager_object_absolute_start']+rm['resource_manager_object_bytes']]
    count=struct.unpack_from('<I',buf,0)[0];ck(count==43941,'original ResourceManager count')
    pos=4;anchors=[]
    for i in range(count):
        n=struct.unpack_from('<I',buf,pos)[0];pos+=4
        ck(0<=n<=2048 and pos+n<=len(buf),'original UTF8 name bound')
        name=buf[pos:pos+n].decode('utf-8');pos=(pos+n+3)&~3
        fid,pid=struct.unpack_from('<iq',buf,pos);pos+=12
        if fid==4:
            ck(pid in objects,'original external PathID resolves')
            klass,size,sha=objects[pid]
            anchors.append(dict(resource_index=i,resource_name=name,file_id=fid,path_id=pid,class_id=klass,object_body_bytes=size,object_body_sha256=sha))
    ck(anchors==rm['anchors'] and len(anchors)==11,'exact original 11 GGM-to-SA0 joins')
    ck(w['dataset_id']=='UNITY_SA0_237_OBJECTINFO_AND_GGM_11_ORIGINAL_TARGET_JOINS_V1','dataset identity')
    return dict(fact='FACT-0343',sharedassets0_original_sha='PASS',ggm_original_sha='PASS',objects=237,reference_joins=len(anchors),unclassified_payload_bytes=0,runtime_eligible=False)
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--sharedassets0',required=True)
    parser.add_argument('--globalgamemanagers',required=True)
    args=parser.parse_args();w=json.loads(W.read_text(encoding='utf-8'))
    print(json.dumps(prove(args.sharedassets0,args.globalgamemanagers,w),sort_keys=True))
    print('FACT0343_ORIGINAL_EXTERNAL_PARENT_PASS')
