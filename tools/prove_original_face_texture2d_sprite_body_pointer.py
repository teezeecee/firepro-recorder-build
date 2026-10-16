#!/usr/bin/env python3
"""FACT-0370 private original retail face Sprite/Texture2D binary source proof."""
import argparse,hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/"canonical/witnesses/RESOBJECT-001/original_face_texture2d_sprite_body_pointer.summary.json"
def sha(b): return hashlib.sha256(b).hexdigest()
def ck(v,msg):
    if not v: raise AssertionError(msg)
def i32(b,o):return struct.unpack_from('<i',b,o)[0]
def i64(b,o):return struct.unpack_from('<q',b,o)[0]
def f32(b,o):return struct.unpack_from('<f',b,o)[0]
def prove(manifest_path,texture_path,sprite_path,ggm_path,metadata_path,s):
    mr=Path(manifest_path).read_bytes()
    ck((len(mr),sha(mr))==(s['private_source_extraction_manifest']['bytes'],s['private_source_extraction_manifest']['sha256']),'source local extraction manifest SHA')
    m=json.loads(mr.decode('utf-8-sig'))
    ck(m['schema']=='FIREPRO_FACT0370_BOUNDED_ORIGINAL_RESOURCES_OBJECTS_V001' and m['source_read_only'] is True,'manifest provenance')
    src=s['original_gamedata']
    ck((m['original_physical_bytes'],m['original_complete_sha256_rechecked'])==(src['resources_original_full_parent_bytes'],src['resources_original_full_parent_sha256']),'external local full SHA assertion')
    g=Path(ggm_path).read_bytes(); b=Path(metadata_path).read_bytes()
    ck((len(g),sha(g))==(src['globalgamemanagers_bytes'],src['globalgamemanagers_sha256']),'original GGM SHA')
    ck((len(b),sha(b))==(src['resources_metadata_bytes'],src['resources_metadata_sha256']),'original metadata SHA')
    ck(struct.unpack_from('>IIIII',b,0)==(1842202,3166587532,17,1842224,0),'original Unity header')
    p=20;q=b.index(0,p);ck(b[p:q]==b'5.6.5p3','original Unity version');p=q+1
    platform,tree,n=struct.unpack_from('<iBI',b,p);p+=9
    ck((platform,tree,n)==(5,0,455),'original Unity type table')
    cls=[]
    for _ in range(n):
        c,d,_script=struct.unpack_from('<iBh',b,p);p+=7
        ck(d==0,'original stripped field')
        if c==114:p+=16
        p+=16;cls.append(c)
    ck(p==17206,'types end offset')
    cnt=struct.unpack_from('<I',b,p)[0];p+=4;p=(p+3)&~3
    ck((cnt,p)==(90992,17212),'source ObjectInfo header boundary')
    ck(sha(b[p:p+20*cnt])=='9d15d5f8280f94bad62b151ee5017db9f99985c834e9f8bbcf86693069dfc463','original ObjectInfo table')
    d=g[122824:122824+4862328]
    ck(sha(d)=='414f1fba01d63bf13a63d82d9b7dbb7fd6223616deb4a57cb3a2ac1f8cbaf9de','original ResourceManager body')
    count=struct.unpack_from('<I',d)[0];ck(count==43941,'original source name count')
    p2=4;rows=[]
    for i in range(count):
        k=struct.unpack_from('<I',d,p2)[0];p2+=4
        ck(k<=2048,'name length')
        name=d[p2:p2+k].decode('utf8');p2=(p2+k+3)&~3
        fid,pid=struct.unpack_from('<iq',d,p2);p2+=12
        if name==s['source_object_names']['resource_name']:rows.append((i,fid,pid))
    ck(p2==2138488,'complete source name table')
    ck(rows==[(3861,5,15464),(3862,5,41553)],'exact original names/PPtrs')
    ck(len(m['records'])==2,'two original object bodies')
    body={28:Path(texture_path).read_bytes(),213:Path(sprite_path).read_bytes()}
    for record in s['source_objects']:
        pid=record['path_id']; i=17212+(pid-1)*20
        rowpid,rel,size,typ=struct.unpack_from('<qIII',b,i)
        ck((rowpid,rel,size,cls[typ],typ)==(pid,record['metadata_data_relative_offset'],record['byte_count'],record['source_class_id'],record['source_type_index']),'source indexed ObjectInfo record')
        ck(record['original_file_absolute_offset']==1842224+rel,'source absolute location')
        original=body[record['source_class_id']]
        ck((len(original),sha(original))==(record['byte_count'],record['sha256']),'original source object SHA')
        ck(struct.unpack_from('<I',original)[0]==13 and original[4:17]==b'b_fc_0000_m_1' and original[17:20]==bytes(3),'original body filename bytes')
        ck(any(x['original_path_id']==pid and x['exported_sha256']==record['sha256'] for x in m['records']),'uploaded source manifest object equality')
    t=body[28];sp=body[213]
    ck(tuple(i32(t,o) for o in (20,24,28,32,76))==(532,700,54497,29,54497),'texture i32 source header')
    ck(t[54577:]==bytes(15),'texture trailing zero bytes')
    ck(tuple(f32(sp,o) for o in (20,24,28,32,60,64,68))==(0.,0.,532.,700.,100.,0.5,0.5),'sprite original rectangle/scale/pivot')
    ck((i32(sp,80),i64(sp,84))==(0,15464),'sprite original internal PPtr -> original Texture2D')
    return {'fact':'FACT-0370','original_face_sprite_pathid':41553,'internal_tex_fileid':0,'internal_tex_pathid':15464,'original_texture_dimensions':[532,700],'source_only':True,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for flag in ('manifest','texture2d','sprite','globalgamemanagers','resources-metadata-prefix'):p.add_argument('--'+flag,required=True)
    a=vars(p.parse_args());s=json.loads(S.read_text())
    print(json.dumps(prove(a['manifest'],a['texture2d'],a['sprite'],a['globalgamemanagers'],a['resources_metadata_prefix'],s),sort_keys=True))
    print('FACT0370_ORIGINAL_FACE_TEXTURE_SPRITE_BINARY_LINK_PASS')
