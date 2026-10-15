#!/usr/bin/env python3
"""FACT-0351 full source-only 440 original first-entry header byte and original DLL witness check."""
import argparse, collections, hashlib, itertools, json, re, struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESPANEL-001/original_440_fpw_first_entry_header_12_byte.summary.json'
DLL=ROOT/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json'
def sha(x):return hashlib.sha256(x).hexdigest()
def ensure(x,msg):
    if not x:raise AssertionError(msg)
def prove(packed,report,w):
    p=w['original_panel'];d=w['original_dll'];o=w['observed']
    raw=Path(packed).read_bytes();manifest=Path(report).read_bytes()
    ensure((len(raw),sha(raw))==(p['bytes'],p['sha256']),'original 440-object pack')
    ensure(sha(manifest)==p['report_sha256'],'original GGM-name ordered report')
    prior=json.loads(DLL.read_text())['dll']
    ensure(prior['sha256']==d['sha256'] and prior['method']['token']==d['methoddef'],'matching original DLL identity')
    ensure(prior['method']['code_sha256']==d['full_il_sha256'] and prior['window']['source_sha256']==d['first_entry_window_il_sha256'],'original first entry IL window SHA')
    ensure(prior['window']['source_byte_offsets_read']==d['first_entry_read_offsets']==[64,65,66,67,68,69,70,74,75],'original code nine source offset reads')
    ensure(prior['window']['cursor_positions_skipped_without_read']==d['first_entry_cursor_skip_offsets']==[71,72,73],'original cursor skips')
    source_fields={f['source']:f['name'] for f in prior['window']['fields'] if isinstance(f['source'],int)}
    ensure(source_fields=={f['source_offset']:f['name'] for f in d['original_field_labels']},'original DLL source field names')
    entries=json.loads(manifest)['Entries'];ensure(len(entries)==440,'original source count')
    rows=[];vectors=[];families=collections.defaultdict(list);seen=set()
    for e in entries:
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        ensure(sha(body)==e['BodySha256'],'whole original body source identity')
        n=struct.unpack_from('<I',body)[0];start=((4+n+3)&~3)+4;src=body[start:-4]
        ensure(start==e['ObservedEmbeddedDataOffset'] and sha(src)==e['ObservedEmbeddedDataSha256'],'original embedded source hash')
        name=e['ResourceName'].split('/')[-1];ensure(name not in seen,'source name uniqueness');seen.add(name)
        ensure(len(src)>76 and src[:2]==b'RS','bounded original first entry source span')
        vector=list(src[64:76]);vectors.append(bytes(vector))
        rows.append({'index':e['SourceIndex'],'path_id':e['PathId'],'name':name,'len':len(src),'first12':vector})
        m=re.fullmatch(r'(fpw_\d+)_([012])',name)
        if m:families[m[1]].append((name,bytes(vector)))
    ensure(len(rows)==o['source_objects']==440,'complete original first-entry index')
    ensure(len(set(vectors))==o['unique_12_byte_headers']==305,'distinct source windows')
    ensure(sha(b''.join(vectors))==o['concatenated_440_12_byte_headers_sha256'],'all original 5280 source bytes SHA')
    ensure(sha(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['indexed_440_source_rows_sha256'],'all indexed original source bytes SHA')
    for s in o['field_stats']:
        assert s['offset'] in range(64,76)
        vals=[row['first12'][s['offset']-64] for row in rows]
        ensure((len(set(vals)),min(vals),max(vals),vals.count(0))==(s['distinct'],s['min'],s['max'],s['zero']),'source distribution '+s['field'])
    ensure(len(families)==o['sibling_families']==65,'source textual families')
    pairs=[(a,b) for x in families.values() for a,b in itertools.combinations(sorted(x),2)]
    ensure(len(pairs)==o['sibling_pairs']==79,'79 original source sibling pairs')
    matching=sum(a[1]==b[1] for a,b in pairs)
    ensure(matching==o['sibling_pairs_matching_full_12_bytes']==75,'exact matching first entry source pair count')
    mismatching=[{'name_a':a[0],'name_b':b[0],'changed_offsets':[64+i for i,(x,y) in enumerate(zip(a[1],b[1])) if x!=y]} for a,b in pairs if a[1]!=b[1]]
    ensure(sorted(mismatching,key=lambda x:(x['name_a'],x['name_b']))==sorted(o['sibling_pairs_with_nonmatching_12_bytes'],key=lambda x:(x['name_a'],x['name_b'])) and len(mismatching)==4,'original first-entry sibling 4-pair identity and byte positions')
    for a in w['anchors']:
        ensure(any(all(row.get(k)==v for k,v in a.items()) for row in rows),'original anchor '+a['name'])
    return {'fact':'FACT-0351','sources':len(rows),'unique_12_byte_source_windows':305,'sibling_pairs_with_same_12_byte_source_window':75,'source_position_comparison_only':True,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--packed',required=True);p.add_argument('--report',required=True)
    a=p.parse_args()
    print(json.dumps(prove(a.packed,a.report,json.loads(W.read_text(encoding='utf8'))),sort_keys=True))
    print('FACT0351_ORIGINAL_FPW_FIRST_ENTRY_SOURCE_INDEX_PASS')
