#!/usr/bin/env python3
"""FACT-0362: read-only exact original 23-token metadata panel and 412-byte helper IL witness."""
import argparse, hashlib, json, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SUM=ROOT/'canonical/witnesses/DLL-001/original_rff_parser_metadata_gettexcellidx.summary.json'
def sha(b): return hashlib.sha256(b).hexdigest()
def ck(cond,message):
    if not cond: raise AssertionError(message)
def prove(witness_file,summary):
    raw=Path(witness_file).read_bytes()
    w=summary['witness']; d=summary['original_dll']; md=summary['metadata_resolution']; h=summary['get_tex_cell_idx']
    ck((len(raw),sha(raw))==(w['bytes'],w['sha256']),'source witness complete byte identity')
    x=json.loads(raw.decode('utf-8-sig'))
    ck((x['schema_version'],x['status'],x['parent_canonical_fact'],x['requested_frontier'])==(w['schema_version'],w['status'],w['parent_canonical_fact'],w['requested_frontier']),'source witness provenance')
    ck((x['dll_size_bytes'],x['dll_sha256'],x['parser_token'],x['parser_il_bytes'],x['parser_il_sha256'])==(d['bytes'],d['sha256'],d['parser_token'],d['parser_il_bytes'],d['parser_il_sha256']),'matching original retail DLL and previous parser SHA')
    tokens=x['metadata_tokens']; ck(len(tokens)==md['requested']==md['resolved']==23,'metadata panel exact length')
    ck(all(t['status']=='RESOLVED_METADATA' for t in tokens),'every exact original metadata token')
    lookup={t['token']:t for t in tokens}
    ck(len(lookup)==len(tokens),'unique original metadata tokens')
    for field in md['fields']:
        t=lookup[field['token']]
        ck(all(t[k]==field[k] for k in ['owner','name','field_type','member_kind']),'field metadata identity '+field['token'])
        ck(t['field_is_static'] is False,'instance field '+field['token'])
    for typ in md['types']:
        t=lookup[typ['token']]
        ck(t['name']==typ['name'] and t['type_full_name']==typ['type_full_name'],'type metadata identity '+typ['token'])
    for c in md['constructors']:
        t=lookup[c['token']]
        ck(t['owner']==c['owner'] and t['name']=='.ctor' and t['parameters']==[],'constructor '+c['token'])
    t=lookup[h['token']]
    ck(t['owner']==h['owner'] and t['name']==h['name'] and t['return_type']==h['return_type'] and t['parameters']==h['parameters'] and t['is_static']==h['is_static'],'original method signature')
    helper=x['parser_called_method']
    ck((helper['token'],helper['owner'],helper['name'],helper['parameters'],helper['return_type'],helper['il_bytes'],helper['il_sha256'])==(h['token'],h['owner'],h['name'],h['parameters'],h['return_type'],h['il_bytes'],h['il_sha256']),'original helper identity')
    b=bytes.fromhex(helper['il_hex'])
    ck(len(b)==412 and sha(b)==h['il_sha256'],'original full 412 byte helper IL SHA')
    ck(h['windows'][0]['start']==0 and h['windows'][-1]['end']==len(b),'five windows full bounds')
    for i,w in enumerate(h['windows']):
        ck(sha(b[w['start']:w['end']])==w['sha256'],'source window '+w['name'])
        if i: ck(h['windows'][i-1]['end']==w['start'],'contiguous source windows')
    # Decode every original IL instruction boundary; reject any unexpected instruction.
    names={0x02:0,0x03:0,0x04:0,0x15:0,0x16:0,0x17:0,0x18:0,0x19:0,0x1a:0,0x1b:0,0x1c:0,0x1d:0,0x1e:0,
           0x1f:1,0x20:4,0x2a:0,0x38:4,0x3c:4,0x40:4,0x54:0,0x59:0,0x7e:4,0x94:0,0x4a:0}
    ins=[]; pos=0
    while pos<len(b):
        start=pos; op=b[pos]; ck(op in names,'unsupported opcode in original source')
        size=names[op];pos+=1+size;ck(pos<=len(b),'truncated instruction operand')
        operand=b[start+1:pos]
        ins.append((start,op,operand))
    boundaries={i[0] for i in ins}; boundaries.add(len(b))
    for start,op,v in ins:
        if op in (0x38,0x3c,0x40):
            target=start+5+struct.unpack('<i',v)[0]
            ck(target in boundaries,'branch targets an instruction boundary')
    ck(b[:6].hex()=='031554041554' and b[-1]==0x2a,'original default out parameters and ret')
    actual_loads=[int.from_bytes(v,'little') for _,op,v in ins if op==0x7e]
    ck(actual_loads==list(range(0x040026e0,0x040026e9)),'nine sequential source lookup FieldDef tokens')
    expected=[(a['char_idx_start'],a['char_idx_end'],a['tex_kind_value'],int(a['lookup_field_token'],16),a['lookup_index_base']) for a in h['bands']]
    ck(expected==[(1,42,0,0x040026e0,1),(43,93,1,0x040026e1,43),(94,143,2,0x040026e2,94),(144,194,3,0x040026e3,144),(195,238,4,0x040026e4,195),(239,286,5,0x040026e5,239),(287,360,6,0x040026e6,287),(361,455,7,0x040026e7,361),(456,573,8,0x040026e8,456)],'exact original ordered branch range table')
    anchors={0:bytes.fromhex('031554041554'),24:bytes.fromhex('021f2b3c'),51:bytes.fromhex('021f5e3c'),79:bytes.fromhex('0220900000003c'),144:bytes.fromhex('0220ef0000003c'),178:bytes.fromhex('02201f0100003c'),212:bytes.fromhex('0220690100003c'),246:bytes.fromhex('0220c80100003c'),280:bytes.fromhex('02203e0200003c'),315:bytes.fromhex('02203e02000059'),325:bytes.fromhex('1f2f400c000000'),346:bytes.fromhex('1f30400c000000'),367:bytes.fromhex('1f31400c000000'),388:bytes.fromhex('1f32400c000000')}
    for pos,seq in anchors.items(): ck(b[pos:pos+len(seq)]==seq, 'source branch and threshold bytes at %d'%pos)
    ck([s['char_idx'] for s in h['special_cases']]==[621,622,623,624],'special absolute source inputs')
    ck([s['tex_kind_value'] for s in h['special_cases']]==[10,11,12,13] and all(s['cell_idx_value']==0 for s in h['special_cases']),'exact special outputs')
    ck(h['original_lookup_array_contents_proven'] is False and h['static_lookup_field_tokens_naming_proven'] is False,'no table data claim')
    return {'fact':'FACT-0362','original_helper_il_sha256':sha(b),'metadata_tokens':len(tokens),'table_backed_ranges':len(actual_loads),'source_only':True,'runtime_eligible':False}
if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--original-witness',required=True)
    a=p.parse_args()
    print(json.dumps(prove(a.original_witness,json.loads(SUM.read_text())),sort_keys=True))
    print('FACT0362_ORIGINAL_RFF_METADATA_GETTEXCELLIDX_ROUTING_PASS')
