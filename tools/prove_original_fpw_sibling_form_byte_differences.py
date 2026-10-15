#!/usr/bin/env python3
"""FACT-0354 original 79 sibling pairs, 3610 per-form source byte alignment/difference index."""
import argparse,collections,hashlib,itertools,json,re,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESPANEL-001/original_79_sibling_pairs_3610_form_byte_differences.summary.json'
D=ROOT/'canonical/witnesses/CAP-R6-001'
def sha(b):return hashlib.sha256(b).hexdigest()
def ensure(ok,msg):
    if not ok:raise AssertionError(msg)
def prove(packed,report,w):
    p=w['original_panel'];d=w['original_dll'];o=w['observed']
    raw=Path(packed).read_bytes();report_bytes=Path(report).read_bytes()
    ensure((len(raw),sha(raw))==(p['bytes'],p['sha256']),'original 440 source resource pack')
    ensure((len(report_bytes),sha(report_bytes))==(p['report_bytes'],p['report_sha256']),'original GGM source report')
    prior=[('skill_data_man_rsf_form_center_pos_signed_vector2.summary.json',[0,1]),('skill_data_man_rsf_form_index_dual_word_read.summary.json',[2,3]),('skill_data_man_rsf_form_offset_pos_and_disp_frame.summary.json',[4,5,6]),('skill_data_man_rsf_form_priorities_and_initial_flags.summary.json',[7,8]),('skill_data_man_rsf_form_flag_bit_or_updates.summary.json',[9]),('skill_data_man_rsf_form_direction_bits_and_altitude.summary.json',[]),('skill_data_man_rsf_form_sound_effect_fields.summary.json',[10,11])]
    read=[]
    for fname,positions in prior:
        x=json.loads((D/fname).read_text(encoding='utf8'))['dll']
        ensure(x['sha256']==d['sha256'] and x['method']['token']==d['methoddef'] and x['method']['code_sha256']==d['method_il_sha256'],'original DLL byte reader SHA '+fname)
        read.extend(positions)
    ensure(read==list(range(12)),'original DLL input byte offsets')
    entries=json.loads(report_bytes)['Entries'];ensure(len(entries)==o['source_objects']==440,'source roster')
    assets={};families=collections.defaultdict(list)
    for e in entries:
        name=e['ResourceName'].split('/')[-1]
        ensure(name not in assets,'duplicate original name')
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        ensure(sha(body)==e['BodySha256'],'original body SHA: '+name)
        n=struct.unpack_from('<I',body)[0];base=((4+n+3)&~3)+4;src=body[base:-4]
        ensure(base==e['ObservedEmbeddedDataOffset'] and len(src)==e['ObservedEmbeddedDataLength'] and sha(src)==e['ObservedEmbeddedDataSha256'],'embedded original source SHA: '+name)
        ensure(src[:2]==b'RS' and (len(src)-64)%12==0,'RS+12 source region')
        vector=list(src[48:64]);prev=0;segments={}
        for slot,end in enumerate(vector):
            ensure(prev<=end<=(len(src)-64)//12,'vector monotone/bounds')
            if end>prev:
                at=64+prev*12;num=src[at]
                ensure(end-prev==num+1,'segment header/step exact byte equality')
                segments[slot]=[bytes(src[at+12*(form+1):at+12*(form+2)]) for form in range(num)]
                ensure(all(len(form)==12 for form in segments[slot]),'form record exactly12')
            prev=end
        ensure(prev==(len(src)-64)//12,'source complete block index')
        assets[name]={'vec':vector,'segments':segments,'src':src,'path_id':e['PathId']}
        m=re.fullmatch(r'(fpw_\d+)_([012])',name)
        if m:families[m.group(1)].append(name)
    ensure(len(families)==o['sibling_families']==65,'original sibling family count')
    ensure(collections.Counter(len(x) for x in families.values())=={2:58,3:7},'original source family variants count')
    pair_rows=[];form_rows=[];pair_suffix=collections.Counter()
    for family,names in sorted(families.items()):
        for name_a,name_b in itertools.combinations(sorted(names),2):
            A,B=assets[name_a],assets[name_b]
            ensure(A['vec']==B['vec'],'exact sibling cumulative vector equality')
            ensure(A['segments'].keys()==B['segments'].keys(),'source family segment-slot identity')
            num=0;same=0;cols=[0]*12;slot_counts=[]
            for slot,fa in A['segments'].items():
                fb=B['segments'][slot]
                ensure(len(fa)==len(fb),'exact same-slot source form count')
                slot_counts.append([slot,len(fa)])
                previous=0 if slot==0 else A['vec'][slot-1]
                for i,(x,y) in enumerate(zip(fa,fb)):
                    num+=1;diff=[i for i in range(12) if x[i]!=y[i]]
                    if not diff:same+=1
                    for b in diff:cols[b]+=1
                    form_rows.append({'family':family,'name_a':name_a,'name_b':name_b,'slot':slot,'form':i,'source_offset':64+12*(previous+1+i),'changed_byte_offsets':diff,'raw_equal':not bool(diff)})
            pair_suffix[name_a.rsplit('_',1)[-1]+'_'+name_b.rsplit('_',1)[-1]]+=1
            pair_rows.append({'family':family,'name_a':name_a,'name_b':name_b,'path_a':A['path_id'],'path_b':B['path_id'],'form_comparisons':num,'identical_forms':same,'changed_forms':num-same,'column_changed_counts':cols,'segment_form_counts':slot_counts,'first_header_equal':A['src'][64:76]==B['src'][64:76]})
    ensure(len(pair_rows)==o['sibling_pair_count']==79 and dict(pair_suffix)==o['pair_suffix_counts'],'complete source sibling pairs')
    ensure(sum(x['form_comparisons'] for x in pair_rows)==o['aligned_form_pair_comparisons']==3610,'all original form comparisons')
    ensure(sum(x['identical_forms'] for x in pair_rows)==o['identical_aligned_form_pairs']==1186,'exact identical source forms')
    ensure(sum(x['changed_forms'] for x in pair_rows)==o['different_aligned_form_pairs']==2424,'exact changed source forms')
    ensure(all(x['changed_forms']>0 for x in pair_rows),'each sibling has source form differences')
    ensure(sum(x['first_header_equal'] for x in pair_rows)==o['sibling_pairs_with_same_first_12_byte_header']==75,'original first segment header match count')
    ensure(len(pair_rows)-sum(x['first_header_equal'] for x in pair_rows)==o['sibling_pairs_with_different_first_12_byte_header']==4,'original 4 header mismatch pairs')
    ensure([sum(row['column_changed_counts'][i] for row in pair_rows) for i in range(12)]==o['original_byte_offsets_with_form_pair_differences'],'per original source form field byte changes')
    ensure([sum(row['column_changed_counts'][i]>0 for row in pair_rows) for i in range(12)]==o['sibling_pairs_with_any_differences_in_each_form_byte_offset'],'source form diff incidence per pair')
    ensure((min(row['form_comparisons'] for row in pair_rows),max(row['form_comparisons'] for row in pair_rows))==(o['pair_comparison_min_form_count'],o['pair_comparison_max_form_count']),'form comparison count extrema')
    ensure(sha(json.dumps(pair_rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['indexed_79_pair_summary_sha256'],'whole 79 original sibling pair source comparison digest')
    ensure(sha(json.dumps(form_rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))==o['indexed_3610_aligned_form_comparison_sha256'],'complete 3610 original source form difference digest')
    for a in w['anchors']:
        ensure(any(all(row.get(k)==v for k,v in a.items()) for row in pair_rows),'original source anchor '+a['family'])
    return {'fact':'FACT-0354','original_440_sources':440,'sibling_pairs':79,'aligned_original_form_pairs':3610,'identical':1186,'different':2424,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--packed',required=True);p.add_argument('--report',required=True)
    a=p.parse_args()
    print(json.dumps(prove(a.packed,a.report,json.loads(W.read_text(encoding='utf8'))),sort_keys=True))
    print('FACT0354_ORIGINAL_SIBLING_FORM_BYTE_DIFF_PASS')
