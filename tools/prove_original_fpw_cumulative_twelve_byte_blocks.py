#!/usr/bin/env python3
"""FACT-0352 original 440 RS cumulative 12-byte block source indexing."""
import argparse, collections, hashlib, json, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESPANEL-001/original_440_fpw_cumulative_twelve_byte_blocks.summary.json'
DLL=ROOT/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json'
def sha(data):
    return hashlib.sha256(data).hexdigest()
def ensure(ok, message):
    if not ok:
        raise AssertionError(message)
def prove(packed, report, witness):
    p=witness['original_panel']; d=witness['original_dll']; o=witness['observed']
    raw=Path(packed).read_bytes()
    manifest_bytes=Path(report).read_bytes()
    ensure((len(raw),sha(raw))==(p['bytes'],p['sha256']),'original complete 440-object source panel SHA')
    ensure((len(manifest_bytes),sha(manifest_bytes))==(p['report_bytes'],p['report_sha256']),'original GGM-linked companion report SHA')
    prior=json.loads(DLL.read_text(encoding='utf8'))['dll']
    ensure(prior['sha256']==d['sha256'] and prior['method']['token']==d['methoddef'],'original DLL identity and MethodDef')
    ensure(prior['method']['code_sha256']==d['full_il_sha256'] and prior['window']['source_sha256']==d['first_entry_il_sha256'],'original DLL first-entry exact IL source')
    ensure(any(x.get('source')==64 and x.get('name')==d['first_entry_field_name'] for x in prior['window']['fields']),'original DLL first-entry source +64 field')
    entries=json.loads(manifest_bytes)['Entries']
    ensure(len(entries)==o['source_objects']==440,'complete original 440 source roster')
    rows=[];flat=[];hist=collections.Counter()
    zero=0;forms=0;total_blocks=0;alignments=0;final_matches=0;steps=0
    seen=set()
    for e in entries:
        name=e['ResourceName'].split('/')[-1]
        ensure(name not in seen,'distinct original source name')
        seen.add(name)
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        ensure(len(body)==e['OriginalByteLength'] and sha(body)==e['BodySha256'],'exact original object source SHA: '+name)
        n=struct.unpack_from('<I',body,0)[0]
        off=((4+n+3)&~3)+4
        source=body[off:-4]
        ensure(off==e['ObservedEmbeddedDataOffset'] and len(source)==e['ObservedEmbeddedDataLength'] and sha(source)==e['ObservedEmbeddedDataSha256'],'exact original embedded source SHA: '+name)
        ensure(len(source)>=76 and source[:2]==b'RS','original embedded source bounds/RS')
        ensure((len(source)-64)%12==0,'original source twelve-byte alignment: '+name)
        alignments+=1
        blocks=(len(source)-64)//12
        vec=list(source[48:64])
        ensure(len(vec)==16 and vec[-1]==blocks,'cumulative vector terminal bound: '+name)
        final_matches+=1
        prev=0;seg=[]
        for slot,endpoint in enumerate(vec):
            ensure(endpoint>=prev and endpoint<=blocks,'monotone cumulative source bounds: '+name)
            if endpoint>prev:
                location=64+12*prev
                length_byte=source[location]
                ensure(endpoint-prev==length_byte+1,'positive source step equals 1+source header byte: '+name)
                seg.append({'slot':slot,'start_block':prev,'end_block':endpoint,'formNum_byte':length_byte,'header_source_offset':location})
                forms+=length_byte;steps+=1
            else:
                zero+=1
            prev=endpoint
        hist[len(seg)]+=1
        total_blocks+=blocks
        rows.append({'index':e['SourceIndex'],'path_id':e['PathId'],'name':name,'len':len(source),'total_blocks':blocks,'vec':vec,'segments':seg})
        flat.extend(seg)
    ensure((alignments,final_matches,steps,zero,total_blocks,forms)==(440,440,1347,5693,24384,23037),'complete 440 source block aggregation')
    ensure((steps,zero,total_blocks,forms)==(o['total_source_segments'],o['zero_step_plateau_positions'],o['total_12_byte_blocks'],o['sum_source_header_first_byte_values']),'witness source aggregation')
    ensure({str(k):v for k,v in sorted(hist.items())}==o['number_of_nonempty_slots_by_source'],'source segment count histogram')
    ensure((min(hist),max(hist))==(o['min_segments_per_source'],o['max_segments_per_source']),'source segment extrema')
    ensure((min(z['total_blocks'] for z in rows),max(z['total_blocks'] for z in rows))==(o['min_total_blocks_per_source'],o['max_total_blocks_per_source']),'total source block extrema')
    ensure((min(s['formNum_byte'] for s in flat),max(s['formNum_byte'] for s in flat))==(o['min_segment_header_first_byte'],o['max_segment_header_first_byte']),'source segment first byte extrema')
    ensure(sha(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['normalized_440_source_segment_rows_sha256'],'full 440 original source row SHA')
    ensure(sha(json.dumps(flat,sort_keys=True,separators=(',',':')).encode('utf8'))==o['normalized_1347_segment_rows_sha256'],'all 1347 segment index SHA')
    for a in witness['anchors']:
        ensure(any(all(row.get(k)==v for k,v in a.items()) for row in rows),'exact original source anchor: '+a['name'])
    return {'fact':'FACT-0352','source_objects':len(rows),'source_12_byte_blocks':total_blocks,'source_segments':steps,'all_exact_source_step_relations':True,'runtime_eligible':False}
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--packed',required=True)
    parser.add_argument('--report',required=True)
    a=parser.parse_args()
    print(json.dumps(prove(a.packed,a.report,json.loads(W.read_text(encoding='utf8'))),sort_keys=True))
    print('FACT0352_ORIGINAL_FPW_CUMULATIVE_TWELVE_BYTE_SOURCE_INDEX_PASS')
