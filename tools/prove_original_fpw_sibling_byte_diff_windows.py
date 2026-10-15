#!/usr/bin/env python3
"""Original 440-source byte-only sibling-window verification for FACT-0350."""
import argparse, collections, hashlib, itertools, json, re, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WITNESS = ROOT / 'canonical/witnesses/RESPANEL-001/original_440_fpw_sibling_byte_diff_windows.summary.json'
def digest(data):
    return hashlib.sha256(data).hexdigest()
def ensure(value, message):
    if not value:
        raise AssertionError(message)
def prove(packed, report, witness):
    p = witness['original_panel']
    raw = Path(packed).read_bytes()
    manifest_bytes = Path(report).read_bytes()
    ensure((len(raw), digest(raw)) == (p['bytes'],p['sha256']), 'original panel SHA / size')
    ensure(digest(manifest_bytes)==p['report_sha256'], 'original report SHA')
    entries=json.loads(manifest_bytes)['Entries']
    o=witness['observed']
    ensure(len(entries)==o['source_objects']==440,'original 440 resource entries')
    families=collections.defaultdict(list)
    source_names=set()
    for e in entries:
        name=e['ResourceName'].split('/')[-1]
        ensure(name not in source_names,'duplicate original resource name')
        source_names.add(name)
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        ensure(digest(body)==e['BodySha256'],'original resource body SHA: '+name)
        namelen=struct.unpack_from('<I',body)[0]
        start=((4+namelen+3)&~3)+4
        ensure(start==e['ObservedEmbeddedDataOffset'],'source payload offset')
        src=body[start:-4]
        ensure(len(src)==e['ObservedEmbeddedDataLength'] and digest(src)==e['ObservedEmbeddedDataSha256'],'embedded payload SHA: '+name)
        ensure(src[:2]==b'RS' and len(src)>76,'original RS embedded bounds')
        m=re.fullmatch(r'(fpw_\d+)_([012])',name)
        if m:
            families[m.group(1)].append((name,e['PathId'],src))
    ensure(len(families)==o['sibling_families']==65,'all original sibling groups')
    ensure(collections.Counter(map(len,families.values()))=={2:58,3:7},'source family sizes')
    rows=[];counts=collections.Counter()
    for family,members in sorted(families.items()):
        members=sorted(members,key=lambda x:x[0])
        for (na,pa,aa),(nb,pb,bb) in itertools.combinations(members,2):
            ensure(len(aa)==len(bb),'original sibling size mismatch')
            offsets=[i for i,(x,y) in enumerate(zip(aa,bb)) if x!=y]
            ensure(offsets,'every sibling pair has distinct embedded source bytes')
            windows=[sum(lo<=i and (hi is None or i<hi) for i in offsets) for lo,hi in [(0,48),(48,64),(64,76),(76,None)]]
            rows.append({'family':family,'name_a':na,'name_b':nb,'path_a':pa,'path_b':pb,'len':len(aa),'diff_count':len(offsets),'window_diffs':windows,'first_diff':offsets[0],'last_diff':offsets[-1],'offsets_sha256':digest(json.dumps(offsets,separators=(',',':')).encode('utf8'))})
            counts[(na[-1],nb[-1])]+=1
    ensure(len(rows)==o['pairwise_comparisons']==79,'all original source sibling pair comparisons')
    ensure(counts=={('0','1'):65,('0','2'):7,('1','2'):7},'original sibling suffix pair counts')
    changed=[sum(row['window_diffs'][i]>0 for row in rows) for i in range(4)]
    changes=[sum(row['window_diffs'][i] for row in rows) for i in range(4)]
    ensure(changed==o['pairs_with_changes']==[62,0,4,79],'distinct original byte-window counts')
    ensure(changes==o['total_changed_bytes_by_range']==[128,0,7,7836],'complete original changed-byte positions')
    ensure(sum(changes)==o['total_changed_bytes_all_pairs']==7971,'all original changed bytes')
    ensure(min(row['diff_count'] for row in rows)==o['min_pair_changed_bytes']==14 and max(row['diff_count'] for row in rows)==o['max_pair_changed_bytes']==417,'source pair minimum/maximum differences')
    ensure(min(row['first_diff'] for row in rows)==o['min_first_changed_index']==9 and max(row['last_diff'] for row in rows)==o['max_last_changed_index']==1283,'source pair offset extrema')
    ensure(digest(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['normalized_79_pair_rows_sha256'],'normalized 79 pair source SHA')
    for a in witness['anchors']:
        ensure(any(all(row.get(k)==v for k,v in a.items()) for row in rows),'original source pair anchor: '+a['family'])
    ensure(witness['dataset_id']=='UNITY_FPW440_ORIGINAL_SIBLING_PAYLOAD_BYTE_DIFF_WINDOWS_V1','source witness dataset identity')
    return {'fact':'FACT-0350','source_pairs_verified':79,'changed_window_pair_counts':changed,'raw_source_only':True,'runtime_eligible':False}
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--packed',required=True)
    parser.add_argument('--report',required=True)
    a=parser.parse_args()
    print(json.dumps(prove(a.packed,a.report,json.loads(WITNESS.read_text(encoding='utf8'))),sort_keys=True))
    print('FACT0350_ORIGINAL_FPW_SIBLING_SOURCE_DIFF_PASS')
