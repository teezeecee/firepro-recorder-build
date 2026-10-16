#!/usr/bin/env python3
"""FACT-0361 read-only original reported retail parser IL and source stride prover."""
import argparse, hashlib, json, struct
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / 'canonical/witnesses/DLL-001/original_fprform_rff_parser_il_stride.summary.json'
def sha(b): return hashlib.sha256(b).hexdigest()
def ck(cond, msg):
    if not cond: raise AssertionError(msg)
def prove(report_file, summary):
    raw = Path(report_file).read_bytes()
    s = summary['original_parser']; st = summary['source_stride']; res = summary['exact_resource_match']
    ck(len(raw) == s['user_original_probe_bytes'] and sha(raw) == s['user_original_probe_sha256'], 'original witness JSON SHA')
    p = json.loads(raw.decode('utf-8-sig'))
    ck(p['schema_version'] == 1 and p['parent_canonical_fact'] == 'FACT-0360' and p['requested_frontier'] == 'FACT-0361', 'source witness identity')
    ck((p['dll_size_bytes'], p['dll_sha256']) == (s['original_dll_bytes'], s['original_dll_sha256']), 'verified matching original DLL')
    ck((p['loader']['token'],p['loader']['owner'],p['loader']['name'],p['loader']['il_bytes'],p['loader']['il_sha256']) == ('0x06001F0F','FormDataMan','LoadFormData_RFF',83,s['parent_loader_il_sha256']), 'already SHA pinned loader source')
    a = p['parser']; ck((a['token'],a['owner'],a['name']) == ('0x06001F12','FormDataMan','ParseFormData_RFF'), 'original parser MethodDef identity')
    ck((a['il_bytes'],a['il_sha256'],a['max_stack'],a['init_locals'],a['exception_clause_count']) == (1153,s['parser_il_sha256'],5,True,0), 'complete parser metadata')
    b = bytes.fromhex(a['il_hex'])
    ck(len(b) == 1153 and sha(b) == a['il_sha256'], 'parser all source bytes SHA')
    ck([(w['start'],w['end']) for w in s['windows']] == [(0,97),(97,306),(306,881),(881,1108),(1108,1153)], 'no gaps source windows')
    for w in s['windows']: ck(sha(b[w['start']:w['end']]) == w['sha256'], 'source subwindow '+w['name'])
    ck((b[0:7].hex(),b[0x29:0x2e].hex(),b[0x6a:0x6f].hex(),b[0xa9:0xae].hex()) == ('0375040400020a','730b1f0006','73081f0006','28181f0006'), 'original class/constructors/call source anchors')
    for pos,to in [(0x1c,0x476),(0x5c,0x45e),(0x462,0x61),(0x47b,0x21)]:
        ck(b[pos] in (0x38,0x3f) and pos+5+struct.unpack_from('<i',b,pos+1)[0] == to, 'original branch target')
    ck(b[0x3c:0x43].hex() == '1f147dcb260004' and b[0x47e:0x481].hex() == 'ffff2a', 'array 20 and ret anchors')
    positions = [i for i,n in enumerate(b) if n == 0x91]
    ck(positions == st['ldelem_u1_il_offsets'] and len(positions) == 13, 'exact source ldelem.u1 offsets')
    ck((b[0x125:0x132].hex(),b[0x371:0x37e].hex()) == ('11081b8d0c0000017dc6260004','11081b8dce0000017dc7260004'), 'per-slot five component and scale allocations')
    ck(b[0x454:0x458].hex() == '0919580d', 'explicit cursor plus three')
    ck(b[0x45e:0x462].hex() == '11071f14' and b[0x476:0x47b].hex() == '1104071759', 'inner 20 and outer length minus one conditions')
    ck((st['per_inner_source_bytes_read'],st['per_inner_explicit_cursor_skip'],st['per_inner_stride_bytes'],st['inner_entries_per_outer']) == (13,3,16,20), 'read+skip stride')
    ck(st['source_bytes_per_form'] == 20*16 == 320, 'real source-proven 320 bytes')
    ck(st['source_allocated_form_array_elements'] == 37999 and st['source_outer_iterations_if_executed'] == 37998, 'original loader array count')
    ck(res['embedded_bytes'] == 12800000 and res['source_320_byte_windows'] == 40000 and res['parser_conditional_bytes_consumed'] == 37998*320 and res['remaining_unread_bytes_under_verified_loader_array_length'] == 12800000-37998*320 == 640640 and res['remaining_320_byte_windows'] == 2002, 'exact original source bounded arithmetic')
    return {'fact':'FACT-0361','parser_il_sha256':sha(b),'per_entry_bytes':16,'per_form_bytes':320,'outer_iterations':37998,'no_runtime_assertions':True}
if __name__ == '__main__':
    x=argparse.ArgumentParser();x.add_argument('--original-witness',required=True);arg=x.parse_args()
    print(json.dumps(prove(arg.original_witness,json.loads(SUMMARY.read_text())),sort_keys=True))
    print('FACT0361_ORIGINAL_PARSER_STATIC_20X16_SOURCE_STRIDE_PASS')
