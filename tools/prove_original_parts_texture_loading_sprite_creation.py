#!/usr/bin/env python3
"""FACT-0367 read-only original private IL witness verification. No original DLL execution."""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=ROOT/'canonical/witnesses/DLL-001/original_parts_texture_loading_sprite_creation.summary.json'
def digest(b):return hashlib.sha256(b).hexdigest()
def ck(x,m):
    if not x:raise AssertionError(m)
def prove(path,s):
    raw=Path(path).read_bytes()
    ck((len(raw),digest(raw))==(s['private_witness']['bytes'],s['private_witness']['sha256']),'private original witness SHA')
    w=json.loads(raw.decode('utf-8-sig'))
    ck((w['schema_version'],w['parent_fact'],w['frontier'])==(1,'FACT-0366','FACT-0367'),'original provenance')
    ck((w['dll_bytes'],w['dll_sha256'])==(s['original_dll']['bytes'],s['original_dll']['sha256']),'retail DLL exact source identity')
    ck(len(w['methods'])==len(s['source_methods'])==6,'six methods')
    bodies={}
    for a,e in zip(w['methods'],s['source_methods']):
        ck(all(a[k]==e[k] for k in ('token','owner','name','il_length','il_sha256')),'method metadata')
        b=bytes.fromhex(a['il_hex'])
        ck(len(b)==e['il_length'] and digest(b)==e['il_sha256'],'full source IL digest')
        bodies[e['token']]=b
    ck(w['windows']==s['source_windows'] and len(w['windows'])==7,'seven original source windows')
    mapping={'GetPartsFileName':'0x060010CD','GetHighlightPartsFileName':'0x060010CE','LoadPartsTex':'0x060010D0','FormRenderer.LoadPartsTex':'0x06001F23','CalcPartsRect':'0x06001F28','InitSprite':'0x06001F20'}
    for e in s['source_windows']:
        b=bodies[mapping[e['method']]]
        ck(digest(b[e['start']:e['end']])==e['sha256'],'window '+e['name'])
    ck(w['source_string_tokens']==s['original_user_strings'],'literal source strings and offsets')
    ck([x['value'] for x in w['source_string_tokens']]==['PartsTex/','/','_h','.png'],'source literal bytes decoded')
    ck(w['member_refs']==s['original_member_refs'],'Unity engine MemberRef signatures')
    def tok(b,off,op,t):
        ck(b[off]==op and struct.unpack_from('<I',b,off+1)[0]==t, 'original opcode/token '+str(off))
    getname=bodies['0x060010CD'];highlight=bodies['0x060010CE'];loader=bodies['0x060010D0'];fload=bodies['0x06001F23'];rect=bodies['0x06001F28'];sprite=bodies['0x06001F20']
    tok(getname,16,0x72,0x70007FAE);tok(getname,28,0x72,0x70000299)
    tok(highlight,17,0x72,0x70007FC2)
    tok(loader,16,0x72,0x7000726C)
    for off,t in [(34,0x060010CF),(41,0x060058C4),(105,0x060010CD)]:tok(loader,off,0x28,t)
    tok(loader,120,0x28,0x0A0006DA)
    tok(fload,1,0x7B,0x04002728)
    tok(fload,15,0x6F,0x060010D0)
    tok(fload,20,0x28,0x0A0009CD)
    for off,t in [(0,0x0400271D),(18,0x0400271D),(36,0x0400271E),(54,0x0400271E)]:tok(rect,off,0x7E,t)
    tok(sprite,344,0x7B,0x04002728)
    tok(sprite,349,0x7E,0x0400271F)
    tok(sprite,357,0x28,0x0A0009C9)
    tok(sprite,364,0x7E,0x0400271F)
    tok(sprite,372,0x28,0x06001F28)
    tok(sprite,422,0x28,0x0A0009CA)
    tok(sprite,427,0x6F,0x0A0002AD)
    return {'fact':'FACT-0367','source_methods':6,'source_windows':7,'source_string_tokens':4,'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--original-witness',required=True)
    a=ap.parse_args();print(json.dumps(prove(a.original_witness,json.loads(S.read_text())),sort_keys=True))
    print('FACT0367_ORIGINAL_TEXTURE_SPRITE_SOURCE_PASS')
