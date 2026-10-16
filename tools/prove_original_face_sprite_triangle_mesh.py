#!/usr/bin/env python3
"""FACT-0371: direct private original Sprite-index and vertex-record byte proof."""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SUMMARY=ROOT/'canonical/witnesses/RESOBJECT-001/original_face_sprite_triangle_mesh_source.summary.json'
def digest(x):return hashlib.sha256(x).hexdigest()
def ensure(c,msg):
    if not c:raise AssertionError(msg)
def prove(sprite_path,texture_path,witness_path,s):
    sr=Path(sprite_path).read_bytes()
    tx=Path(texture_path).read_bytes()
    wraw=Path(witness_path).read_bytes()
    ensure((len(sr),digest(sr))==(s['source_sprite']['bytes'],s['source_sprite']['sha256']),'original Sprite file SHA')
    ensure((len(tx),digest(tx))==(s['source_texture']['bytes'],s['source_texture']['sha256']),'original paired Texture2D SHA')
    ensure((len(wraw),digest(wraw))==(s['private_witness']['bytes'],s['private_witness']['sha256']),'private parsed witness SHA')
    w=json.loads(wraw.decode('utf-8'))
    ensure((w['parent_fact'],w['frontier'],w['source_id'])==('FACT-0370','FACT-0371','RESOBJECT-001'),'private witness provenance')
    r=s['regions'];g=s['geometry']
    ensure(struct.unpack_from('<I',sr,r['index_byte_count_field_offset'])[0]==r['index_byte_count'],'original index byte count field')
    ix=sr[r['index_buffer_start']:r['index_buffer_end']]
    ensure(len(ix)==r['index_byte_count'] and digest(ix)==r['index_raw_sha256'],'source indices SHA')
    ensure(sr[r['index_padding_start']:r['index_padding_end']]==bytes(r['index_padding_zero_bytes']),'index alignment bytes')
    ensure(digest(sr[r['descriptor_start']:r['descriptor_end']])==r['descriptor_sha256'],'descriptor source SHA')
    ensure(struct.unpack_from('<I',sr,r['vertex_count_offset'])[0]==g['vertex_count'],'source vertex count field')
    ensure(struct.unpack_from('<I',sr,r['vertex_bytes_field_offset'])[0]==r['vertex_byte_count'],'source packed vertex bytes field')
    raw=sr[r['vertex_buffer_start']:r['vertex_buffer_end']]
    ensure(len(raw)==g['vertex_count']*g['vertex_stride_bytes'] and digest(raw)==r['vertex_raw_sha256'],'vertex source SHA')
    ensure(len(sr[r['tail_start']:r['tail_end']])==r['tail_byte_count'] and digest(sr[r['tail_start']:r['tail_end']])==r['tail_sha256'],'original bounded tail')
    ixvals=struct.unpack('<%dH'%(len(ix)//2),ix)
    ensure((len(ixvals),min(ixvals),max(ixvals),len(set(ixvals)))==(g['index_count'],g['minimum_index'],g['maximum_index'],g['unique_index_count']),'exact index extrema/counts')
    ensure(set(ixvals)==set(range(g['vertex_count'])),'all original vertex IDs referenced')
    tris=[ixvals[i:i+3] for i in range(0,len(ixvals),3)]
    ensure(len(tris)==g['triangle_count'] and all(len(set(t))==3 for t in tris),'nondegenerate original triple indices')
    ensure([list(t) for t in tris[:6]]==g['first_6_triplets'],'first original triples')
    ensure([list(t) for t in tris[-6:]]==g['last_6_triplets'],'last original triples')
    verts=[struct.unpack_from('<5f',raw,i*g['vertex_stride_bytes']) for i in range(g['vertex_count'])]
    ensure(len(verts)*5==g['vertex_float32_count'],'float32 source count')
    ensure(all(v[2:]==(0.0,0.0,0.0) for v in verts),'all last 3 float32 source words zero')
    bounds=[min(v[0] for v in verts),max(v[0] for v in verts),min(v[1] for v in verts),max(v[1] for v in verts)]
    ensure(bounds==g['xy_min_max_float32'],'all source XY extrema')
    signs=[(verts[b][0]-verts[a][0])*(verts[c][1]-verts[a][1])-(verts[b][1]-verts[a][1])*(verts[c][0]-verts[a][0]) for a,b,c in tris]
    ensure((sum(x<0 for x in signs),sum(x>0 for x in signs),sum(x==0 for x in signs))==(245,0,0),'original triangle winding direction')
    wm=w['mesh_structure']
    ensure(wm['index_raw_sha256']==r['index_raw_sha256'] and wm['vertex_sha256']==r['vertex_raw_sha256'],'private witness source window digests')
    ensure((wm['index_value_count'],wm['triangle_triplet_count'],wm['vertex_count'])==(735,245,327),'private witness topology counts')
    return {'fact':'FACT-0371','source_sprite_sha':'PASS','index_count':len(ixvals),'triangles':len(tris),'vertex_count':len(verts),'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--sprite',required=True);p.add_argument('--texture',required=True);p.add_argument('--original-witness',required=True)
    a=p.parse_args()
    s=json.loads(SUMMARY.read_text())
    print(json.dumps(prove(a.sprite,a.texture,a.original_witness,s),sort_keys=True))
    print('FACT0371_ORIGINAL_FACE_SPRITE_GEOMETRY_PASS')
