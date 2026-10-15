#!/usr/bin/env python3
"""FACT-0355 prove original 23037 source form numeric input decode via exact retail-DLL IL witnesses."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/'canonical/witnesses/RESPANEL-001/original_23037_fpw_form_numeric_fields.summary.json'
D=R/'canonical/witnesses/CAP-R6-001'
def sha(b):return hashlib.sha256(b).hexdigest()
def signed8(b):return b-256 if b>=128 else b
def ensure(v,reason):
    if not v:raise AssertionError(reason)
def decode(b,index,path_id,name,slot,form,pos):
    a,b1,c,d,e,f,g,h,i,k,l,m=b
    return {
        'index':index,'path_id':path_id,'name':name,'slot':slot,'form':form,'source_offset':pos,
        'center_x':signed8(a),'center_y':signed8(b1),'formIdx':(c<<8)|d,
        'offset_x_x2':signed8(e)*2,'offset_y_x2':signed8(f)*2,
        'dispFrm':g,'formPri':(h>>6)&3,'ringPri':(h>>3)&7,
        'flags_initial':i,
        'flags_final':i|(0x400 if k&1 else 0)|(0x800 if k&2 else 0)|(0x100 if k&4 else 0)|(0x200 if l&32 else 0),
        'dir_LR_bit':1 if k&8 else 0,'dir_UD_bit':1 if k&128 else 0,
        'altitude_bits':(k>>4)&7,'ringVibration':(l>>3)&3,'seID':m&63,'seLevel':(m>>6)&3,
        'effectID_initial':-1}
def prove(packed,report,w):
    original=w['original_panel'];dll=w['original_dll'];obs=w['observed']
    raw=Path(packed).read_bytes();report_data=Path(report).read_bytes()
    ensure((len(raw),sha(raw))==(original['bytes'],original['sha256']),'exact original 440 pack')
    ensure((len(report_data),sha(report_data))==(original['report_bytes'],original['report_sha256']),'exact original GGM report')
    ensure(sum(x['source_bytes_advanced'] for x in dll['reader_windows'])==12,'original FormDispInfo 12 input bytes')
    for item in dll['reader_windows']:
        src=json.loads((D/item['witness']).read_text(encoding='utf8'))['dll']
        ensure(src['sha256']==dll['sha256'] and src['method']['token']==dll['methoddef'],'original matched DLL witness identity '+item['witness'])
        ensure(src['method']['code_sha256']==dll['method_il_sha256'],'original whole parser IL SHA '+item['witness'])
        win=src['window']
        ensure((win['start_il'],win['end_exclusive_il'],win['source_sha256'])==(item['start_il'],item['end_exclusive_il'],item['il_sha256']),'original IL source byte reader '+item['witness'])
    entries=json.loads(report_data)['Entries']
    ensure(len(entries)==obs['source_objects']==440,'complete original GGM panel source names')
    rows=[];raw_forms=[];seg_count=0
    for entry in entries:
        name=entry['ResourceName'].split('/')[-1]
        body=raw[entry['PackedOffset']:entry['PackedOffset']+entry['OriginalByteLength']]
        ensure(sha(body)==entry['BodySha256'],'original object byte SHA '+name)
        name_len=struct.unpack_from('<I',body,0)[0]
        embedded_offset=((4+name_len+3)&~3)+4
        src=body[embedded_offset:-4]
        ensure(embedded_offset==entry['ObservedEmbeddedDataOffset'] and len(src)==entry['ObservedEmbeddedDataLength'] and sha(src)==entry['ObservedEmbeddedDataSha256'],'original TextAsset embedded byte SHA '+name)
        ensure(src[:2]==b'RS' and (len(src)-64)%12==0,'source header & block alignment '+name)
        cumulative=src[48:64];prev=0
        for slot,end in enumerate(cumulative):
            ensure(end>=prev and end<=(len(src)-64)//12,'source vector bounds '+name)
            if end>prev:
                pos=64+12*prev;cnt=src[pos]
                ensure(end-prev==cnt+1,'source header form count '+name)
                seg_count+=1
                for form in range(cnt):
                    off=pos+12*(form+1);part=bytes(src[off:off+12])
                    ensure(len(part)==12,'bounded source form body '+name)
                    rows.append(decode(part,entry['SourceIndex'],entry['PathId'],name,slot,form,off))
                    raw_forms.append(part)
            prev=end
        ensure(prev==(len(src)-64)//12,'complete original source segment coverage '+name)
    ensure((seg_count,len(rows),12*len(rows))==(obs['segment_header_blocks'],obs['form_record_count'],obs['form_source_bytes'])==(1347,23037,276444),'complete original 23037 source form rows')
    ensure(sha(b''.join(raw_forms))==obs['original_concatenated_23037_form_raw_bytes_sha256'],'same original 23037 raw form bytes SHA')
    row_raw=json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8')
    ensure(sha(row_raw)==obs['full_original_23037_decoded_numeric_rows_sha256'],'full original 23037 decoded scalar source index SHA')
    ensure(len(set(row['formIdx'] for row in rows))==obs['distinct_packed_formIdx_values'],'original formIdx cardinality')
    for field,distribution in obs['numeric_field_distributions'].items():
        c=collections.Counter(row[field] for row in rows)
        ensure({'distinct':len(c),'min':min(c),'max':max(c),'zero':c[0]}==distribution,'numeric original source field distribution '+field)
    for anchor in w['anchors']:
        ensure(any(row==anchor for row in rows),'original source decoded anchor '+anchor['name'])
    return {'fact':'FACT-0355','source_objects':len(entries),'form_source_records':len(rows),'original_form_input_fields':len(obs['numeric_field_distributions']),'decoded_row_sha256':sha(row_raw),'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--packed',required=True);p.add_argument('--report',required=True)
    a=p.parse_args()
    print(json.dumps(prove(a.packed,a.report,json.loads(W.read_text(encoding='utf8'))),sort_keys=True))
    print('FACT0355_ORIGINAL_23037_NUMERIC_FORM_SOURCE_DECODE_PASS')
