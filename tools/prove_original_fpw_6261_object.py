#!/usr/bin/env python3
"""FACT-0345: read-only exact original 2376-byte resource + metadata + GGM join."""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESOBJ-001/fpw_6261_exact_2376_byte_object.summary.json'
def sha(data):return hashlib.sha256(data).hexdigest()
def ck(p,msg):
    if not p: raise AssertionError(msg)
def prove(body_path,metadata_path,ggm_path,w):
    b=Path(body_path).read_bytes()
    m=Path(metadata_path).read_bytes()
    g=Path(ggm_path).read_bytes()
    obj=w['object_source'];meta=w['metadata_source'];gg=w['original_ggm_source'];layout=w['original_object_layout']
    ck((len(b),sha(b))==(obj['size_bytes'],obj['sha256']),'original object body complete SHA')
    ck((len(m),sha(m))==(meta['bytes'],meta['sha256']),'original source metadata complete SHA')
    ck((len(g),sha(g))==(gg['bytes'],gg['sha256']),'original source GGM complete SHA')
    ck(struct.unpack_from('>IIIII',m,0)==(1842202,3166587532,17,1842224,0),'original Unity header')
    off=meta['original_objectinfo_row_offset']
    row=m[off:off+meta['original_objectinfo_row_bytes']]
    ck(len(row)==20 and sha(row)==meta['original_objectinfo_row_sha256'],'exact original object row SHA')
    pid,rel,size,ti=struct.unpack('<qIII',row)
    ck((pid,rel,size,ti)==(meta['path_id'],meta['object_relative_offset'],meta['object_byte_size'],meta['type_index']),'exact ObjectInfo fields')
    ck(meta['metadata_objectinfo_table_start']+(pid-1)*20==off,'metadata row ordinal')
    ck(meta['class_id']==49,'original class identity anchor')
    ck(meta['data_offset']+rel==obj['original_absolute_offset'] and obj['original_absolute_offset']+size==obj['original_end_exclusive'],'original byte-window bounds')
    n=struct.unpack_from('<I',b,layout['name_length_offset'])[0]
    ck(n==layout['name_length_u32']==8,'name u32')
    ck(b[4:4+n].decode('ascii')==layout['name_ascii']=='fpw_6261','exact original source name bytes')
    data_len=struct.unpack_from('<I',b,layout['embedded_byte_length_offset'])[0]
    ck(data_len==layout['embedded_length_u32']==2356,'source embedded length')
    payload=b[layout['embedded_bytes_start']:layout['embedded_bytes_end']]
    ck(len(payload)==data_len and sha(payload)==layout['embedded_bytes_sha256'],'actual original embedded data SHA')
    ck(payload[:2].hex()==layout['first_two_embedded_bytes_hex']=='5253','literal payload leading bytes')
    ck(b[layout['terminal_four_bytes_start']:].hex()==layout['terminal_four_bytes_hex']=='00000000','exact original terminal source bytes')
    ck(layout['fully_accounted_bytes']==4+n+4+data_len+4==len(b),'no unparsed byte windows')
    rm=g[gg['original_resource_manager_start']:gg['original_resource_manager_end']]
    pos=4
    count=struct.unpack_from('<I',rm,0)[0]
    ck(count==gg['name_index_count']==43941,'original name source row count')
    hits=[]
    for i in range(count):
        name_size=struct.unpack_from('<I',rm,pos)[0];pos+=4
        ck(0<=name_size<=2048 and pos+name_size<len(rm),'name bytes bounds')
        name=rm[pos:pos+name_size].decode('utf-8')
        end=pos+name_size
        pos=(end+3)&~3
        ck(rm[end:pos]==bytes(pos-end),'name alignment bytes')
        fid,refpid=struct.unpack_from('<iq',rm,pos);pos+=12
        if (fid,refpid)==(gg['matched_file_id'],gg['matched_path_id']): hits.append((i,name))
    ck(pos==gg['name_index_end_relative'],'source name index exact end')
    ck(hits==[(gg['matched_index'],gg['matched_name'])] and gg['matched_occurrence_count']==len(hits),'unique exact original GGM source name numeric match')
    ck(w['dataset_id']=='UNITY_RESOURCES_FPW6261_SINGLE_OBJECT_ORIGINAL_BYTES_V1','source dataset ID')
    return {'fact':'FACT-0345','original_object_sha':'PASS','original_metadata_sha':'PASS','original_ggm_sha':'PASS','object_bytes':len(b),'embedded_bytes':data_len,'source_ggm_matches':len(hits),'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--original-object',required=True)
    p.add_argument('--metadata-prefix',required=True)
    p.add_argument('--globalgamemanagers',required=True)
    args=p.parse_args()
    w=json.loads(W.read_text(encoding='utf-8'))
    print(json.dumps(prove(args.original_object,args.metadata_prefix,args.globalgamemanagers,w),sort_keys=True))
    print('FACT0345_ORIGINAL_OBJECT_SOURCE_PASS')
