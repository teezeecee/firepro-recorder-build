#!/usr/bin/env python3
"""FACT-0372: read-only original Texture2D/Crunch container proof against private evidence."""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SUMMARY=ROOT/'canonical/witnesses/RESOBJECT-001/original_face_texture2d_crn_container.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(c,msg):
    if not c:raise AssertionError(msg)
def big(b,off,length):return int.from_bytes(b[off:off+length],'big')
def prove(texture_file,witness_file,s):
    original=Path(texture_file).read_bytes()
    raw=Path(witness_file).read_bytes()
    src=s['source_texture'];wm=s['private_witness']
    need((len(original),sha(original))==(src['original_bytes'],src['sha256']),'full original object digest')
    need((len(raw),sha(raw))==(wm['bytes'],wm['sha256']),'private witness digest')
    w=json.loads(raw.decode('utf-8'))
    need(w['fact_id']=='FACT-0372' and w['parent_fact']=='FACT-0371','provenance')
    need(w['original_texture']['sha256']==src['sha256'],'source SHA provenance')
    u=s['unity_fields'];h=s['crn_header'];a=s['crn_regions']
    need(struct.unpack_from('<i',original,20)[0]==u['width'],'Unity width')
    need(struct.unpack_from('<i',original,24)[0]==u['height'],'Unity height')
    need(struct.unpack_from('<i',original,32)[0]==u['texture_format_numeric'],'Unity format29')
    need(struct.unpack_from('<i',original,76)[0]==u['encoded_data_size_field_at76'],'Unity data size')
    blob=original[u['encoded_object_offset']:u['encoded_object_end_exclusive']]
    need(len(blob)==u['complete_image_size'] and sha(blob)=='1dde001e0c8b0409d0fa453193fedbef5f0bb174916ec0e474269b6b930ebd06','original encoded container region')
    need(original[u['encoded_object_end_exclusive']:]==bytes(u['tail_zero_bytes']),'original trailer zero')
    fields=[('signature_hex',0,2),('header_size',2,2),('data_size',6,4),('width',12,2),('height',14,2),('levels',16,1),('faces',17,1),('crn_format',18,1),('flags',19,2),('reserved',21,4),('userdata0',25,4),('userdata1',29,4)]
    for name,offset,length in fields:
        got=blob[offset:offset+length].hex(' ') if name=='signature_hex' else big(blob,offset,length)
        need(got==h[name],f'CRN {name}')
    need(big(blob,4,2)==int(h['header_crc16_hex'],16) and big(blob,10,2)==int(h['data_crc16_hex'],16),'stored CRC fields (not recalculated)')
    paloffs={'color_endpoints':33,'color_selectors':41,'alpha_endpoints':49,'alpha_selectors':57}
    cursor=h['header_size']
    for name,off in paloffs.items():
        v=a[name]
        need((big(blob,off,3),big(blob,off+3,3),big(blob,off+6,2))==(v['offset'],v['size'],v['entry_count']),name+' palette fields')
        need(v['offset']==cursor and v['end']==cursor+v['size'],name+' boundaries')
        cursor=v['end']
    tables=a['tables'];mip=a['mip0']
    need((big(blob,65,2),big(blob,67,3))==(tables['size'],tables['offset']),'tables fields')
    need(tables['offset']==cursor and tables['end']==cursor+tables['size'],'tables partition')
    need(big(blob,70,4)==mip['offset'] and mip['offset']==tables['end'],'level0 original offset')
    need(mip['end']==len(blob) and mip['size']==len(blob)-mip['offset'],'full CRN partition')
    need(w['crn_sections']==a,'private derived section agreement')
    return {'fact':'FACT-0372','original_digest':'PASS','encoded_bytes':len(blob),'crn_header_bytes':h['header_size'],'level0_encoded_bytes':mip['size'],'decoded_pixels':False,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--texture',required=True);p.add_argument('--original-witness',required=True)
    x=p.parse_args()
    print(json.dumps(prove(x.texture,x.original_witness,json.loads(SUMMARY.read_text())),sort_keys=True))
    print('FACT0372_ORIGINAL_CRN_CONTAINER_PASS')
