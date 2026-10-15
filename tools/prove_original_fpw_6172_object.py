#!/usr/bin/env python3
"""FACT-0346 original read-only fpw_6172 resource body + metadata + GGM verifier."""
import argparse,hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/'canonical/witnesses/RESOBJ-002/fpw_6172_exact_1716_byte_object.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(v,s):
    if not v:raise AssertionError(s)
def prove(body,metadata,ggm,w,prior=None):
    b=Path(body).read_bytes();m=Path(metadata).read_bytes();g=Path(ggm).read_bytes()
    o=w['object_source'];a=w['metadata_source'];z=w['ggm_source'];p=w['payload']
    ck((len(b),sha(b))==(o['size_bytes'],o['sha256']),'original object SHA')
    ck((len(m),sha(m))==(a['bytes'],a['sha256']),'original metadata SHA')
    ck((len(g),sha(g))==(z['bytes'],z['sha256']),'original GGM SHA')
    ck(struct.unpack_from('>IIIII',m,0)==(1842202,3166587532,17,1842224,0),'Unity original header')
    row=m[a['row_offset']:a['row_offset']+20]
    ck(len(row)==20 and sha(row)==a['row_sha256'],'ObjectInfo row hash')
    pid,rel,size,ti=struct.unpack('<qIII',row)
    ck((pid,rel,size,ti,a['class_id'])==(21353,1955351216,1716,4,49),'original object identity')
    ck(17212+(pid-1)*20==a['row_offset'],'ObjectInfo row ordinal')
    ck(a['data_offset']+rel==o['original_absolute_offset']==1957193440,'original object start')
    ck(a['data_offset']+rel+size==o['original_end_exclusive']==1957195156,'original object end')
    n=struct.unpack_from('<I',b,0)[0]
    ck(n==p['name_len']==8 and b[4:4+n]==b'fpw_6172','original source name')
    k=struct.unpack_from('<I',b,12)[0]
    ck(k==p['embedded_len']==1696,'original embedded len')
    rs=b[16:16+k]
    ck(len(rs)==k and sha(rs)==p['embedded_sha256'],'original opaque embedded SHA')
    ck(rs[:2].hex()==p['embedded_prefix_hex']=='5253','literal RS prefix')
    ck(b[16+k:].hex()==p['trailer_hex']=='00000000','trailing original zeros')
    ck(16+k+4==len(b)==p['bytes_accounted'],'entire object byte accounting')
    rm=g[z['resource_manager_absolute_start']:z['resource_manager_absolute_end']]
    c=struct.unpack_from('<I',rm,0)[0];ck(c==z['names']==43941,'original ResourceManager count')
    hits=[];pos=4
    for i in range(c):
        length=struct.unpack_from('<I',rm,pos)[0];pos+=4
        ck(length<=2048 and pos+length<=len(rm),'source name bounds')
        name=rm[pos:pos+length].decode('utf8')
        end=pos+length;pos=(end+3)&~3
        ck(rm[end:pos]==bytes(pos-end),'zero source alignment')
        fid,refpid=struct.unpack_from('<iq',rm,pos);pos+=12
        if (fid,refpid)==(z['file_id'],z['path_id']):hits.append((i,name))
    ck(pos==2138488,'ResourceManager index end')
    ck(hits==[(z['name_index'],z['name'])]==[(43890,'wrestleranimation/fpw_6172')],'unique original GGM name join')
    ck(o['original_prior_export_sha256']==o['sha256'],'previous original export SHA')
    if prior is not None:
        old=Path(prior).read_bytes()
        ck(old==b and sha(old)==o['original_prior_export_sha256'],'prior original export equality')
    ck(o['original_full_file_rehashed'] is False,'full file hash scope')
    ck(w['dataset_id']=='UNITY_RESOURCES_FPW6172_SINGLE_OBJECT_ORIGINAL_BYTES_V1','dataset id')
    return {'fact':'FACT-0346','body_sha':'PASS','metadata_sha':'PASS','ggm_sha':'PASS','original_bytes':len(b),'embedded_bytes':len(rs),'original_named_pointer_count':len(hits),'prior_export_checked':prior is not None,'runtime_eligible':False}
if __name__=='__main__':
    x=argparse.ArgumentParser()
    x.add_argument('--original-object',required=True)
    x.add_argument('--metadata-prefix',required=True)
    x.add_argument('--globalgamemanagers',required=True)
    x.add_argument('--prior-export')
    a=x.parse_args()
    print(json.dumps(prove(a.original_object,a.metadata_prefix,a.globalgamemanagers,json.loads(W.read_text()),a.prior_export),sort_keys=True))
    print('FACT0346_ORIGINAL_OBJECT_SOURCE_PASS')
