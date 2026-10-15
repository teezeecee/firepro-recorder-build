#!/usr/bin/env python3
"""FACT-0356: paired original 12-byte forms -> DLL-derived numeric input differences.
Suffix names establish source alignment only, never runtime mirror or facing.
"""
import argparse,collections,hashlib,itertools,json,re,struct
from pathlib import Path
from prove_original_fpw_23037_form_numeric_fields import decode, prove as prove_numeric
from prove_original_fpw_sibling_form_byte_differences import prove as prove_bytes
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'canonical/witnesses/RESPANEL-001'
W=BASE/'original_3610_sibling_numeric_source_differences.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def check(ok,msg):
    if not ok:raise AssertionError(msg)
def digest(rows):
    return sha(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))
def prove(packed,report,w):
    prior_b=json.loads((BASE/'original_79_sibling_pairs_3610_form_byte_differences.summary.json').read_text())
    prior_n=json.loads((BASE/'original_23037_fpw_form_numeric_fields.summary.json').read_text())
    check(prove_bytes(packed,report,prior_b)['aligned_original_form_pairs']==3610,'prior original 3610 raw form comparisons')
    check(prove_numeric(packed,report,prior_n)['form_source_records']==23037,'prior exact DLL-decoded original source inputs')
    raw=Path(packed).read_bytes();report_raw=Path(report).read_bytes();panel=w['original_panel'];o=w['observed']
    check((len(raw),sha(raw))==(panel['bytes'],panel['sha256']),'original pack identity')
    check((len(report_raw),sha(report_raw))==(panel['report_bytes'],panel['report_sha256']),'original GGM report identity')
    entries=json.loads(report_raw)['Entries'];check(len(entries)==440,'complete GGM source objects')
    assets={};families=collections.defaultdict(list)
    for e in entries:
        name=e['ResourceName'].rsplit('/',1)[-1]
        body=raw[e['PackedOffset']:e['PackedOffset']+e['OriginalByteLength']]
        check(sha(body)==e['BodySha256'],'original byte body '+name)
        n=struct.unpack_from('<I',body,0)[0];off=((4+n+3)&~3)+4;src=body[off:-4]
        check(off==e['ObservedEmbeddedDataOffset'] and sha(src)==e['ObservedEmbeddedDataSha256'],'embedded exact original source '+name)
        check(src[:2]==b'RS' and (len(src)-64)%12==0,'original RS form alignment '+name)
        vec=src[48:64];prev=0;slots={}
        for slot,end in enumerate(vec):
            check(prev<=end<=(len(src)-64)//12,'source vector bounds')
            if end>prev:
                start=64+12*prev;count=src[start]
                check(end-prev==count+1,'original source header form count')
                slots[slot]=[src[start+12*(i+1):start+12*(i+2)] for i in range(count)]
                check(all(len(x)==12 for x in slots[slot]),'full original 12 byte forms')
            prev=end
        check(prev==(len(src)-64)//12,'complete original source boundaries')
        assets[name]=(vec,slots)
        m=re.fullmatch(r'(fpw_\d+)_([012])',name)
        if m:families[m.group(1)].append(name)
    check(len(families)==65,'complete original sibling name families')
    field_names=list(decode(bytes(12),0,0,'',0,0,0))[6:]
    check(len(field_names)==17,'proven 17 numeric source field keys')
    count=collections.Counter();any_pair=collections.Counter()
    numeric_rows=[];raw_rows=[];anchors=[]
    for family,names in sorted(families.items()):
        for a,b in itertools.combinations(sorted(names),2):
            av,aseg=assets[a];bv,bseg=assets[b]
            check(av==bv and aseg.keys()==bseg.keys(),'sibling source vectors aligned')
            local=collections.Counter();total=0;equal=0
            for slot,aa in aseg.items():
                bb=bseg[slot];check(len(aa)==len(bb),'original sibling form counts')
                prev=av[slot-1] if slot else 0
                for i,(x,y) in enumerate(zip(aa,bb)):
                    X=decode(x,0,0,'',0,0,0);Y=decode(y,0,0,'',0,0,0)
                    changed=[k for k in field_names if X[k]!=Y[k]]
                    raw_changed=[j for j in range(12) if x[j]!=y[j]]
                    check(bool(changed)==bool(raw_changed),'raw vs numeric form equality correspondence')
                    total+=1;equal+=not changed
                    for k in changed:count[k]+=1;local[k]+=1
                    numeric_rows.append({'family':family,'name_a':a,'name_b':b,'slot':slot,'form':i,'changed_numeric_fields':changed,'numeric_equal':not bool(changed)})
                    raw_rows.append({'family':family,'name_a':a,'name_b':b,'slot':slot,'form':i,'source_offset':64+12*(prev+1+i),'changed_byte_offsets':raw_changed,'raw_equal':not bool(raw_changed)})
            for k in field_names:any_pair[k]+=bool(local[k])
            if family in ('fpw_2004','fpw_6048','fpw_6161') and a.endswith('_0') and b.endswith('_1'):
                anchors.append({'family':family,'name_a':a,'name_b':b,'forms':total,'same':equal,'fields_change_counts':{k:local[k] for k in field_names if local[k]}})
    check(digest(raw_rows)==prior_b['observed']['indexed_3610_aligned_form_comparison_sha256']==o['parent_raw_comparison_rows_sha256'],'same original raw comparison SHA as FACT-0354')
    check(prior_n['observed']['full_original_23037_decoded_numeric_rows_sha256']==o['parent_all_23037_numeric_rows_sha256'],'same original numeric parent SHA as FACT-0355')
    check(len(numeric_rows)==o['aligned_form_comparisons']==3610,'original 3610 numeric comparisons')
    check(sum(x['numeric_equal'] for x in numeric_rows)==o['same_numeric_forms']==1186,'original numeric equality count')
    check(len(numeric_rows)-o['same_numeric_forms']==o['different_numeric_forms']==2424,'original numeric changes')
    check(digest(numeric_rows)==o['full_3610_numeric_change_index_sha256'],'entire original 3610 pair numeric digest')
    check({k:count[k] for k in field_names}==o['numeric_fields_changed_form_counts'],'all 17 source field change counts')
    check({k:any_pair[k] for k in field_names}==o['numeric_fields_changed_pair_incidence'],'all 17 sibling pair incidence counts')
    check(sum(count.values())==o['total_numeric_field_changes']==7681,'numeric source difference incidence sum')
    check(anchors==w['anchors'],'original indexed anchors')
    return {'fact':'FACT-0356','aligned_source_forms':len(numeric_rows),'identical_numeric':1186,'changed_numeric':2424,'numeric_row_sha256':digest(numeric_rows),'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--packed',required=True);ap.add_argument('--report',required=True)
    args=ap.parse_args()
    print(json.dumps(prove(args.packed,args.report,json.loads(W.read_text())),sort_keys=True))
    print('FACT0356_3610_ORIGINAL_SIBLING_NUMERIC_DIFFERENCES_PASS')
