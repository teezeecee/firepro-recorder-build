#!/usr/bin/env python3
"""FACT-0353 read-only proof of complete 23037 original twelve-byte form source index and matching DLL byte reader."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/'canonical/witnesses/RESPANEL-001/original_440_fpw_23037_form_source_blocks.summary.json'
D=R/'canonical/witnesses/CAP-R6-001'
def sha(b):return hashlib.sha256(b).hexdigest()
def ensure(x,m):
    if not x:raise AssertionError(m)
def prove(packed,report,w):
    p=w['original_panel'];d=w['original_dll'];o=w['observed']
    raw=Path(packed).read_bytes();reportbytes=Path(report).read_bytes()
    ensure((len(raw),sha(raw))==(p['bytes'],p['sha256']),'original packed 440 resource checksum')
    ensure((len(reportbytes),sha(reportbytes))==(p['report_bytes'],p['report_sha256']),'original source report checksum')
    offsets=[]
    for spec in d['form_reader_windows']:
        prior=json.loads((D/spec['dll_witness']).read_text(encoding='utf8'))['dll']
        ensure(prior['sha256']==d['sha256'] and prior['method']['token']==d['methoddef'],'original DLL identity '+spec['fact'])
        ensure(prior['method']['code_sha256']==d['method_il_sha256'],'original original parser code hash '+spec['fact'])
        win=prior['window']
        ensure(win['start_il']==spec['il_start'] and win['end_exclusive_il']==spec['il_end'] and win['source_sha256']==spec['il_sha256'],'original IL source byte window '+spec['fact'])
        ensure(len(spec['bytes'])==spec['bytes_consumed'],'original reader byte count '+spec['fact'])
        offsets.extend(spec['bytes'])
    ensure(offsets==list(range(12)) and sum(z['bytes_consumed'] for z in d['form_reader_windows'])==12,'original 12-byte ordered nested per-form source reader')
    srcs=json.loads(reportbytes)['Entries'];ensure(len(srcs)==o['source_objects']==440,'original source roster')
    source_rows=[];form_rows=[];forms=[];headers=[];column_count=collections.Counter()
    nonzero=collections.Counter();anchor_map={x['name']:x for x in w['anchors']};found=set();idxset=set()
    for e in srcs:
        name=e['ResourceName'].split('/')[-1]
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        ensure(sha(body)==e['BodySha256'],'whole original object body')
        n=struct.unpack_from('<I',body,0)[0];start=((4+n+3)&~3)+4
        src=body[start:-4]
        ensure(start==e['ObservedEmbeddedDataOffset'] and len(src)==e['ObservedEmbeddedDataLength'] and sha(src)==e['ObservedEmbeddedDataSha256'],'original embedded source body')
        ensure(src[:2]==b'RS' and (len(src)-64)%12==0,'source RS and aligned source record region')
        vec=list(src[48:64]);prev=0;segments=[];own_forms=0
        for slot,endpoint in enumerate(vec):
            ensure(prev<=endpoint<=(len(src)-64)//12,'original cumulative step bounds')
            if endpoint>prev:
                at=64+12*prev;first=src[at:at+12]
                nform=src[at];ensure(endpoint-prev==1+nform and len(first)==12,'exact source segment form record count')
                headers.append(first);segforms=[]
                for form in range(nform):
                    foffset=at+12*(form+1);fb=src[foffset:foffset+12]
                    ensure(len(fb)==12,'complete original form source block')
                    form_rows.append({'index':e['SourceIndex'],'path_id':e['PathId'],'name':name,'slot':slot,'form':form,'source_offset':foffset,'raw_sha256':sha(fb)})
                    forms.append(fb);segforms.append(fb)
                    idx=(fb[2]<<8)|fb[3];idxset.add(idx)
                    for i,b in enumerate(fb):column_count[(i,b)]+=1
                    for key,yes in [
                        ('signed_centers_nonzero',fb[0]!=0 or fb[1]!=0),
                        ('signed_offsets_nonzero',fb[4]!=0 or fb[5]!=0),
                        ('nonzero_dispFrm',fb[6]!=0),
                        ('nonzero_priorities',fb[7]!=0),
                        ('nonzero_flags',fb[8]!=0),
                        ('nonzero_direction_flags',fb[9]!=0),
                        ('nonzero_sound_field10',fb[10]!=0),
                        ('nonzero_sound_field11',fb[11]!=0)]:
                        nonzero[key]+=bool(yes)
                segments.append({'slot':slot,'source_offset':at,'form_count':nform,'form_block_count':len(segforms),'raw_12byte_header_sha256':sha(first),'form_body_sha256':sha(b''.join(segforms))})
                own_forms+=nform
            prev=endpoint
        ensure(prev==(len(src)-64)//12,'complete source block coverage')
        source_rows.append({'index':e['SourceIndex'],'path_id':e['PathId'],'name':name,'len':len(src),'segments':segments,'total_form_rows':own_forms})
        if name in anchor_map:
            a=anchor_map[name]
            firstform=src[76:88];ensure(len(firstform)==12,'original first source form anchor')
            ensure((e['SourceIndex'],e['PathId'],sha(firstform),(firstform[2]<<8)|firstform[3],segments[0]['form_count'])==(a['index'],a['path_id'],a['first_form_sha256'],a['first_form_two_byte_value'],a['segment0_form_count']),'original anchor values '+name)
            ensure(a['first_form_source_offset']==76,'source anchor first form offset')
            found.add(name)
    ensure(found==set(anchor_map),'all original source anchors')
    ensure((len(headers),len(forms),len(forms)*12,len(headers)+len(forms))==(o['source_segments'],o['source_form_records'],o['source_form_bytes'],o['total_twelve_byte_source_blocks'])==(1347,23037,276444,24384),'entire source body consumption')
    ensure(len(set(forms))==o['distinct_form_record_raw_12_byte_patterns']==15571,'unique original twelve byte form source patterns')
    ensure((len(idxset),min(idxset),max(idxset))==(o['distinct_two_byte_big_endian_source_values_at_form_relative_2_3'],o['minimum_two_byte_big_endian_source_value_at_form_relative_2_3'],o['maximum_two_byte_big_endian_source_value_at_form_relative_2_3'])==(7214,100,37998),'two byte source value distribution')
    ensure(sha(b''.join(forms))==o['concat_original_form_source_bytes_sha256'],'complete original 276444-byte form source digest')
    ensure(sha(json.dumps(source_rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['normalized_440_source_rows_sha256'],'complete original 440 segment body SHA')
    ensure(sha(json.dumps(form_rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['normalized_23037_form_rows_sha256'],'complete original 23037 form source provenance SHA')
    for stat in o['form_record_byte_column_stats']:
        i=stat['byte_offset'];counts={v:column_count[(i,v)] for v in range(256) if column_count[(i,v)]}
        ensure((len(counts),min(counts),max(counts),counts.get(0,0))==(stat['distinct_unsigned_values'],stat['minimum'],stat['maximum'],stat['zero_value_count']),'exact form source column '+str(i))
    ensure(dict(nonzero)==o['nonzero_field_byte_group_counts'],'original form source group values')
    return {'fact':'FACT-0353','original_source_count':len(source_rows),'source_segments':len(headers),'twelve_byte_source_forms':len(forms),'unique_form_source_patterns':len(set(forms)),'layout_matches_prior_exact_original_dll_input_read_order':True,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--packed',required=True);p.add_argument('--report',required=True)
    a=p.parse_args()
    print(json.dumps(prove(a.packed,a.report,json.loads(W.read_text(encoding='utf8'))),sort_keys=True))
    print('FACT0353_ORIGINAL_23037_FORM_SOURCE_BLOCKS_PASS')
