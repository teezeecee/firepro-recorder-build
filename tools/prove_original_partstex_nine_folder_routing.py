#!/usr/bin/env python3
"""Verify FACT-0368 against user-owned, SHA-pinned original DLL IL witness."""
import argparse, hashlib, json, struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'canonical/witnesses/DLL-001/original_partstex_nine_folder_name_routing.summary.json'
def digest(data): return hashlib.sha256(data).hexdigest()
def require(ok,message):
    if not ok: raise AssertionError(message)
def prove(path,s):
    raw=Path(path).read_bytes()
    require((len(raw),digest(raw))==(s['private_witness']['bytes'],s['private_witness']['sha256']),'private original witness SHA')
    w=json.loads(raw.decode('utf-8'))
    require((w['schema_version'],w['parent_fact'],w['frontier'])==(1,'FACT-0367','FACT-0368'),'original witness provenance')
    require((w['dll_bytes'],w['dll_sha256'])==(s['original_dll']['bytes'],s['original_dll']['sha256']),'retail DLL SHA')
    require(len(w['methods'])==len(s['methods'])==6,'six complete source methods')
    bodies={}
    for m,e in zip(w['methods'],s['methods']):
        require(all(m[k]==e[k] for k in ('token','owner','name','il_length','il_sha256')),'original method metadata')
        il=bytes.fromhex(m['il_hex'])
        require(len(il)==e['il_length'] and digest(il)==e['il_sha256'],'complete method IL byte SHA')
        bodies[e['name']]=il
    for e in s['source_windows']:
        il=bodies[e['method']]
        require(digest(il[e['start']:e['end']])==e['sha256'],'source window '+e['name'])
    def tok(il,offset,opcode,token):
        require(il[offset]==opcode and struct.unpack_from('<I',il,offset+1)[0]==int(token,16),'original opcode/token '+str(offset))
    cc=bodies['.cctor']
    for group,offsets in [('folder_strings',[16,24,32,40,48,56,64,72,80]),('base_prefix_strings',[98,110,122,134,146,158,170]),('parts_code_strings',[194,206,218,230,242,254,266,278,290])]:
        items=w[group]
        for e,off in zip(items,offsets):
            require(e['il_offset']==off,'original token offset')
            tok(cc,off,0x72,e['token'])
        expected=([x['folder'] for x in s['source_mapping']] if group=='folder_strings' else s['base_prefixes'] if group=='base_prefix_strings' else [x['filename_code'] for x in s['source_mapping']])
        require([x['value'] for x in items]==expected,'original source table values '+group)
    for offset,token in [(86,'0x04000E22'),(182,'0x04000E23'),(302,'0x04000E24')]:
        tok(cc,offset,0x80,token)
    kind=bodies['GetPartsTexKind']
    require(kind[0:8]==bytes.fromhex('02 18 18 6f 18 00 00 0a'),'source substring(2,2)')
    tok(kind,11,0x7e,'0x04000E24')
    tok(kind,17,0x6f,'0x0A000718')
    name=bodies['GetPartsFileName']
    tok(name,1,0x28,'0x060010CA')
    require(name[8:16]==bytes.fromhex('15 40 02 00 00 00 14 2a'),'negative kind path')
    tok(name,16,0x72,'0x70007FAE')
    tok(name,21,0x7e,'0x04000E22')
    tok(name,28,0x72,'0x70000299')
    tok(name,34,0x28,'0x0A00054D')
    hi=bodies['GetHighlightPartsFileName']
    tok(hi,2,0x28,'0x060010CD')
    tok(hi,17,0x72,'0x70007FC2')
    tok(hi,22,0x28,'0x0A000012')
    base=bodies['GetBaseTexType']
    require(base[13:23]==bytes.fromhex('1f 0a 17 6f 18 00 00 0a 0a 15'),'base substring(10,1)')
    for x in w['tag_name_strings']:
        tok(bodies['GetPartsTexKindFromTag'],x['il_offset'],0x72,x['token'])
    require([x['value'] for x in w['tag_name_strings']]==[x['tag'] for x in s['source_mapping']],'original source tag names')
    require([x['value'] for x in w['construction_strings']]==['PartsTex/','/','_h'],'original path constants')
    return {'fact':'FACT-0368','source_method_count':6,'original_windows':8,'folder_count':9,'runtime_eligible':False}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--original-witness',required=True)
    a=parser.parse_args()
    print(json.dumps(prove(a.original_witness,json.loads(S.read_text())),sort_keys=True))
    print('FACT0368_ORIGINAL_PARTSTEX_NINE_FOLDER_SOURCE_PASS')
