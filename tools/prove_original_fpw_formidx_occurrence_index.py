#!/usr/bin/env python3
"""FACT-0357 exact original formIdx numeric input occurrence index; source only."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
from prove_original_fpw_23037_form_numeric_fields import prove as prove_numeric
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/'canonical/witnesses/RESPANEL-001'
W=P/'original_23037_fpw_formidx_occurrence_index.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def digest(rows):return sha(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))
def check(q,msg):
    if not q:raise AssertionError(msg)
def prove(packed,report,w):
    prior=json.loads((P/'original_23037_fpw_form_numeric_fields.summary.json').read_text())
    check(prove_numeric(packed,report,prior)['form_source_records']==23037,'original full 23037 numeric source decode')
    o=w['observed'];p=w['original_panel']
    raw=Path(packed).read_bytes();rb=Path(report).read_bytes()
    check((len(raw),sha(raw))==(p['bytes'],p['sha256']),'original source pack')
    check((len(rb),sha(rb))==(p['report_bytes'],p['report_sha256']),'original GGM panel report')
    check(prior['observed']['full_original_23037_decoded_numeric_rows_sha256']==o['prior_23037_numeric_source_rows_sha256'],'exact original numeric source row parent')
    rows=collections.defaultdict(list);form_total=0;segments=0
    entries=json.loads(rb)['Entries']
    check(len(entries)==o['source_objects']==440,'original GGM source object count')
    for e in entries:
        name=e['ResourceName'].rsplit('/',1)[-1]
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        check(sha(body)==e['BodySha256'],'original exact resource bytes '+name)
        n=struct.unpack_from('<I',body)[0];off=((4+n+3)&~3)+4;src=body[off:-4]
        check(off==e['ObservedEmbeddedDataOffset'] and len(src)==e['ObservedEmbeddedDataLength'] and sha(src)==e['ObservedEmbeddedDataSha256'],'original RS embedded source SHA '+name)
        check(src[:2]==b'RS' and (len(src)-64)%12==0,'original source form region '+name)
        prev=0
        for slot,end in enumerate(src[48:64]):
            check(prev<=end<=(len(src)-64)//12,'original cumulative vector bounds '+name)
            if end>prev:
                start=64+12*prev;count=src[start]
                check(end-prev==count+1,'original form segment header count '+name)
                segments+=1
                for form in range(count):
                    offset=start+12*(form+1);part=src[offset:offset+12]
                    check(len(part)==12,'original 12-byte input bounds')
                    key=(part[2]<<8)|part[3]
                    rows[key].append({'index':e['SourceIndex'],'path_id':e['PathId'],'name':name,'slot':slot,'form':form,'source_offset':offset})
                    form_total+=1
            prev=end
        check(prev==(len(src)-64)//12,'full source vector coverage '+name)
    check(segments==1347 and form_total==o['source_form_records']==23037,'all original segment/form source positions')
    keys=sorted(rows);check(len(keys)==o['distinct_formIdx_values']==7214,'distinct source input index values')
    check((keys[0],keys[-1])==(o['formIdx_min'],o['formIdx_max']),'source input range')
    output=[{'formIdx':k,'occurrences':len(rows[k]),'distinct_source_objects':len({v['path_id'] for v in rows[k]}),'locations':rows[k]} for k in keys]
    check(digest(output)==o['complete_7214_value_occurrence_index_sha256'],'all 7214 original keyed source positions SHA')
    hist=collections.Counter(len(v) for v in rows.values())
    check(digest(sorted(hist.items()))==o['frequency_histogram_sha256'],'full original source multiplicity histogram SHA')
    check(hist[1]==o['single_occurrence_values']==3852,'single-source occurrence input values')
    check(len(keys)-hist[1]==o['multiple_occurrence_values']==3362,'repeated source inputs')
    check(sum(k*v for k,v in hist.items() if k>1)==o['occurrences_of_repeated_values']==19185,'all repeated-source form occurrences')
    multi=[v for v in rows.values() if len({x['path_id'] for x in v})>1]
    check(len(multi)==o['multiple_source_object_values']==2348,'inputs spanning distinct GGM resources')
    check(sum(len(v) for v in multi)==o['occurrences_of_multiple_source_object_values']==16012,'cross-source occurrence count')
    check(len(keys)-len(multi)==o['one_source_object_values']==4866,'single object input count')
    check(len(rows[o['max_occurrence_value']])==o['max_occurrences']==858,'maximum original input multiplicity')
    check(max(len({x['path_id'] for x in v}) for v in rows.values())==o['max_distinct_source_objects']==294,'maximum different source objects')
    for anchor in w['anchors']:
        x=rows[anchor['formIdx']]
        check(anchor=={'formIdx':anchor['formIdx'],'occurrences':len(x),'distinct_source_objects':len({r['path_id'] for r in x}),'first_location':x[0],'last_location':x[-1]},'original GGM occurrence anchor '+str(anchor['formIdx']))
    return {'fact':'FACT-0357','source_forms':form_total,'distinct_formIdx':len(keys),'full_occurrence_sha256':digest(output),'runtime_eligible':False}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--packed',required=True);parser.add_argument('--report',required=True)
    args=parser.parse_args();print(json.dumps(prove(args.packed,args.report,json.loads(W.read_text())),sort_keys=True));print('FACT0357_ORIGINAL_FORMIDX_SOURCE_OCCURRENCES_PASS')
