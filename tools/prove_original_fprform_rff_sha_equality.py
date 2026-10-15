#!/usr/bin/env python3
"""FACT-0360 read-only original Windows bounded SHA report and independently hashed export."""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESOBJ-003/original_fprform_rff_body_sha_and_embedded_bytes.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(v,m):
    if not v:raise AssertionError(m)
def check_report(r,w):
    p=w['user_original_probe_report']
    ck(r['schema_version']==1 and r['checkpoint']==p['checkpoint'] and r['source']==p['source'],'original probe identity')
    ck(r['parent_file'].replace('/','\\').lower().endswith('\\resources.assets'),'original parent basename')
    expected={'parent_file_length':'reported_parent_file_length','original_parent_full_file_sha_rechecked':'original_parent_full_file_sha_rechecked','original_metadata_prefix_bytes':'metadata_prefix_bytes','original_metadata_prefix_sha256':'metadata_prefix_sha256','unity_class_id':'unity_class_id','path_id':'path_id','original_object_absolute_offset':'object_absolute_offset','original_object_bytes':'object_bytes','original_object_sha256':'reported_original_object_sha256','prior_uploaded_uabe_export_sha256':'reported_previous_uabe_sha256','original_equals_prior_export':'reported_equal','further_original_body_upload_needed':'reported_further_upload_needed','runtime_formdata_or_sprite_mapping_proven':'reported_runtime_mapping_proven'}
    for k,v in expected.items():ck(type(r[k]) is type(p[v]) and r[k]==p[v],'original probe field '+k)
    ck(r['original_equals_prior_export'] is True and r['original_parent_full_file_sha_rechecked'] is False,'no original parent full hash claim')
def prove(report_path,export_path,metadata_path,w,parent_path=None):
    reportbytes=Path(report_path).read_bytes();report=json.loads(reportbytes.decode('utf-8-sig'))
    obj=Path(export_path).read_bytes();meta=Path(metadata_path).read_bytes()
    source=w['user_original_probe_report'];ext=w['matching_export'];info=w['original_metadata_prefix']
    ck((len(reportbytes),sha(reportbytes))==(source['bytes'],source['sha256']),'actual original probe JSON SHA')
    check_report(report,w)
    ck((len(meta),sha(meta))==(info['bytes'],info['sha256']),'original metadata prefix SHA')
    row=meta[info['objectinfo_row_offset']:info['objectinfo_row_offset']+20]
    ck(sha(row)==info['objectinfo_row_sha256'] and len(row)==20,'original serialized ObjectInfo source row hash')
    p,rel,size,ti=struct.unpack('<qIII',row)
    ck({'path_id':p,'payload_relative_offset':rel,'declared_body_bytes':size,'type_index':ti}==info['objectinfo_row'],'original ObjectInfo source fields')
    ck(info['data_offset']+rel==report['original_object_absolute_offset'],'original ObjectInfo absolute bounds')
    ck((len(obj),sha(obj))==(ext['size_bytes'],ext['sha256'])==(size,report['original_object_sha256']),'exact previous UABE exported object SHA equals Windows original source digest')
    x=ext['textasset_wrapper'];n=struct.unpack_from('<I',obj,0)[0]
    ck(n==x['name_length']==11 and obj[4:4+n].decode('utf8')==x['name_utf8'],'serialized original name and length')
    ck(obj[15]==x['alignment_byte_at_15']==0,'name alignment zero padding')
    count=struct.unpack_from('<I',obj,x['embedded_data_size_field_offset'])[0]
    ck(count==x['embedded_data_length']==12800000 and x['embedded_data_start']==20 and x['embedded_data_end_exclusive']==20+count,'TextAsset embedded byte length and bounds')
    ck(sha(obj[:24])==x['first_24_bytes_sha256'],'TextAsset header SHA')
    ck(sha(obj[20:20+count])==x['embedded_data_sha256'],'complete 12800000 original matched embedded bytes SHA')
    ck(obj[20+count:].hex()==x['trailing_bytes_hex'] and len(obj)==20+count+4,'exact 4 original terminal bytes')
    if parent_path:
        with Path(parent_path).open('rb') as f:
            f.seek(0,2);ck(f.tell()==report['parent_file_length'],'original parent exact length')
            f.seek(0);ck(sha(f.read(info['bytes']))==info['sha256'],'original parent prefix independently checked')
            f.seek(report['original_object_absolute_offset'])
            parentbody=f.read(report['original_object_bytes'])
            ck(len(parentbody)==len(obj) and sha(parentbody)==sha(obj),'optional direct original parent object bytes agree')
    ck(count//320==w['observed']['source_320_byte_divisibility']==40000 and count%320==0,'numeric divisibility only')
    ck(w['observed']['source_320_byte_interpretation_proven'] is False,'no source record semantics established')
    return {'fact':'FACT-0360','path_id':p,'object_bytes':len(obj),'object_sha256':sha(obj),'embedded_bytes':count,'embedded_sha256':sha(obj[20:20+count]),'parent_full_file_sha_rechecked':False,'runtime_eligible':False}
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--report',required=True);a.add_argument('--export',required=True);a.add_argument('--metadata-prefix',required=True);a.add_argument('--original-parent',default=None)
    x=a.parse_args()
    print(json.dumps(prove(x.report,x.export,x.metadata_prefix,json.loads(W.read_text()),x.original_parent),sort_keys=True))
    print('FACT0360_ORIGINAL_FPRFORM_RFF_SHA_EQUALITY_AND_ENVELOPE_PASS')
