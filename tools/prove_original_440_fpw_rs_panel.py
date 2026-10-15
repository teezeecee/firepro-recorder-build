#!/usr/bin/env python3
"""FACT-0347 original-byte, 440-source, read-only proof; never executes RS data."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
WITNESS=ROOT/'canonical/witnesses/RESPANEL-001/original_440_fpw_rs_panel.summary.json'
def sha(data): return hashlib.sha256(data).hexdigest()
def ck(cond,why):
    if not cond: raise AssertionError(why)
def prove(packed_path,report_path,metadata_path,ggm_path,w,prior_6172=None,prior_6261=None):
    b=Path(packed_path).read_bytes();reportbytes=Path(report_path).read_bytes()
    m=Path(metadata_path).read_bytes();g=Path(ggm_path).read_bytes()
    p=w['original_packed'];q=w['original_companion'];a=w['original_metadata'];z=w['original_ggm'];obs=w['observations']
    ck((len(b),sha(b))==(p['bytes'],p['sha256']),'packed original bytes complete SHA')
    ck((len(reportbytes),sha(reportbytes))==(q['bytes'],q['sha256']),'report bytes complete SHA')
    ck((len(m),sha(m))==(a['bytes'],a['sha256']),'original metadata bytes complete SHA')
    ck((len(g),sha(g))==(z['bytes'],z['sha256']),'original GGM bytes complete SHA')
    j=json.loads(reportbytes)
    ck(j['Schema']=='FIREPRO_ORIGINAL_NAMED_FPW_RESOURCE_PANEL_V001','report schema')
    ck(j['ReadOnlyGameFiles'] is True and j['OriginalFullResourcesShaRechecked'] is False,'read-only bounded source scope')
    ck(j['OriginalResourcesMetadataPrefixSha256']==a['sha256'],'report metadata source identity')
    ck(j['OriginalGlobalgamemanagersSha256']==z['sha256'],'report GGM source identity')
    ck(j['PackedSha256']==p['sha256'] and j['NamedFpwObjectTotalBytes']==p['bytes'],'report pack source identity')
    ck(struct.unpack_from('>IIIII',m,0)==(1842202,3166587532,17,1842224,0),'original Unity header')
    pos=20;pos=m.index(b'\x00',pos)+1
    platform,tree,count=struct.unpack_from('<iBI',m,pos);pos+=9
    ck((platform,tree,count)==(5,0,455),'original type table count')
    types=[]
    for _ in range(count):
        classid,deleted,_script=struct.unpack_from('<iBh',m,pos)
        ck(deleted==0,'original type flags')
        types.append(classid);pos+=39 if classid==114 else 23
    ck(pos==17206 and types[a['type_index']]==a['class_id']==49,'original ClassID49 type index4')
    objects_count=struct.unpack_from('<I',m,pos)[0]
    pos=(pos+4+3)&~3
    ck(objects_count==90992 and pos==a['object_info_table_start']==17212,'original object rows')
    rm=g[z['resource_manager_start']:z['resource_manager_end']]
    number=struct.unpack_from('<I',rm,0)[0]
    ck(number==z['resource_names']==43941,'GGM ResourceManager source records')
    pos=4;named=[]
    for i in range(number):
        n=struct.unpack_from('<I',rm,pos)[0];pos+=4
        ck(0<=n<=2048 and pos+n<=len(rm),'original GGM name bounds')
        name=rm[pos:pos+n].decode('utf8');end=pos+n;pos=(end+3)&~3
        ck(rm[end:pos]==bytes(pos-end),'original GGM zero name alignment')
        fid,pathid=struct.unpack_from('<iq',rm,pos);pos+=12
        if name.startswith(z['selected_prefix']):
            ck(fid==z['source_file_id'],'original GGM source fileID')
            named.append((i,name,pathid))
    ck(pos==2138488,'complete original GGM named index')
    ck(len(named)==obs['source_object_count']==440,'complete named original fpw source selection')
    ck(named[0][0]==z['selected_first_index']==43501 and named[-1][0]==z['selected_last_index']==43940,'original fpw group index bounds')
    ck([x[0] for x in named]==list(range(43501,43941)),'contiguous original source indices')
    entries=j['Entries']
    ck(len(entries)==len(named)==j['NamedFpwObjectCount'],'report original count')
    fields=q['normalized_440_index_fields']
    mapped=[{key:row[key] for key in fields} for row in entries]
    digest=sha(json.dumps(mapped,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))
    ck(digest==q['normalized_440_index_sha256'],'complete 440-row source witness SHA')
    off=0;payloads=[];bodyshas=set();embeddedshas=collections.Counter();nameLens=collections.Counter();payloadOffsets=collections.Counter();bodySizes=[]
    anchors={x['name']:x for x in w['anchors']}
    encountered=set()
    for (index,name,pathid),e in zip(named,entries):
        ck((e['SourceIndex'],e['ResourceName'],e['PathId'])==(index,name,pathid),'GGM name and original PathID join')
        ck(1<=pathid<=90992,'original ObjectInfo PathID bounds')
        rowoffset=a['object_info_table_start']+(pathid-1)*20
        rawrow=m[rowoffset:rowoffset+20]
        ck(rowoffset==e['OriginalObjectInfoRowOffset'] and len(rawrow)==20 and sha(rawrow)==e['OriginalObjectInfoRowSha256'],'original ObjectInfo exact source row')
        rowpid,rel,size,ti=struct.unpack('<qIII',rawrow)
        ck((rowpid,size,ti)==(pathid,e['OriginalByteLength'],a['type_index']),'original metadata body length and TypeIndex')
        ck(e['ClassId']==types[ti]==49 and e['OriginalAbsoluteOffset']==a['data_offset']+rel,'original physical object address')
        ck(e['PackedOffset']==off,'contiguous source pack in original GGM name order')
        obj=b[off:off+size]
        ck(len(obj)==size and sha(obj)==e['BodySha256'],'complete body original SHA')
        ck(e['ObservedEnvelope'] is True and e['ObservedLiteralRsPrefix'] is True,'observed source envelope declarations')
        namelen=struct.unpack_from('<I',obj,0)[0];expected=name.split('/')[-1].encode('ascii')
        ck(namelen==len(expected) and obj[4:4+namelen]==expected,'original ASCII resource object name')
        aftername=4+namelen;aligned=(aftername+3)&~3
        ck(obj[aftername:aligned]==bytes(aligned-aftername),'name 4-byte alignment zeros')
        embeddedlen=struct.unpack_from('<I',obj,aligned)[0];start=aligned+4
        payload=obj[start:start+embeddedlen]
        ck(start==e['ObservedEmbeddedDataOffset'] and embeddedlen==e['ObservedEmbeddedDataLength'],'embedded original length and offset')
        ck(len(payload)==embeddedlen and sha(payload)==e['ObservedEmbeddedDataSha256'],'original embedded data SHA')
        ck(payload[:2]==b'RS' and struct.unpack_from('<I',payload,2)[0]==embeddedlen,'literal RS and source u32 observed embedded-size equality')
        ck(obj[start+embeddedlen:]==b'\x00\x00\x00\x00' and start+embeddedlen+4==size,'fully consumed zero-trailer envelope')
        if name in anchors:
            x=anchors[name]
            ck((index,pathid,off,size,sha(obj))==(x['index'],x['path_id'],x['packed_offset'],x['bytes'],x['sha256']),'independent source anchor match')
            encountered.add(name)
        nameLens[namelen]+=1;payloadOffsets[start]+=1
        bodySizes.append(size);bodyshas.add(sha(obj));embeddedshas[sha(payload)]+=1;payloads.append(payload)
        off+=size
    ck(encountered==set(anchors) and off==len(b)==p['bytes'],'all 440 packed rows and source anchors')
    ck(dict((str(k),v) for k,v in nameLens.items())==obs['name_length_count'],'original object-name lengths')
    ck(dict((str(k),v) for k,v in payloadOffsets.items())==obs['embedded_byte_offset_count'],'original embedded offsets')
    ck((len(bodyshas),min(bodySizes),max(bodySizes))==(440,obs['min_body_bytes'],obs['max_body_bytes']),'original whole-body uniqueness and size bounds')
    ck(sum(len(x) for x in payloads)==obs['embedded_total_bytes']==320768,'total embedded source bytes')
    ck(sha(b''.join(payloads))==obs['embedded_concatenated_sha256'],'concatenated embedded original SHA')
    ck(len(embeddedshas)==obs['unique_embedded_payload_shas']==431,'unique embedded original SHA count')
    ck(sum(v-1 for v in embeddedshas.values())==obs['duplicate_embedded_pairs']==9,'identical embedded pair count')
    ck(all(len(x)%4==0 for x in payloads),'observed embedded original size alignment')
    for external,n in [(prior_6172,'wrestleranimation/fpw_6172'),(prior_6261,'wrestleranimation/fpw_6261')]:
        if external:
            anchor=anchors[n]
            ck(Path(external).read_bytes()==b[anchor['packed_offset']:anchor['packed_offset']+anchor['bytes']],'independent previously proven exact source object bytes')
    ck(w['dataset_id']=='UNITY_ORIGINAL_NAMED_FPW_RS_440_OBJECT_PANEL_V1','dataset identity')
    ck(w['original_packed']['full_parent_rehashed_in_probe'] is False,'full parent SHA scope')
    return {'fact':'FACT-0347','original_packed_sha':'PASS','report_sha':'PASS','original_metadata_sha':'PASS','original_ggm_sha':'PASS','object_count':440,'original_object_bytes':330116,'embedded_original_bytes':320768,'distinct_embedded_sha':431,'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--packed',required=True)
    ap.add_argument('--report',required=True)
    ap.add_argument('--metadata-prefix',required=True)
    ap.add_argument('--globalgamemanagers',required=True)
    ap.add_argument('--prior-6172')
    ap.add_argument('--prior-6261')
    args=ap.parse_args()
    w=json.loads(WITNESS.read_text(encoding='utf-8'))
    print(json.dumps(prove(args.packed,args.report,args.metadata_prefix,args.globalgamemanagers,w,args.prior_6172,args.prior_6261),sort_keys=True))
    print('FACT0347_ORIGINAL_440_SOURCE_PANEL_PASS')
