"""FACT-0365 standalone static original-source checkpoint without bundled retail IL."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/'canonical/witnesses/DLL-001/original_rff_gettexcellidx_direct_callers_partsnum.summary.json').read_text())
f=json.loads((ROOT/'canonical/facts/FACT-0365-original-rff-texcell-consumers-partsnum-counter.json').read_text())
r=json.loads((ROOT/'canonical/transition_registry.json').read_text())
prev=json.loads((ROOT/'canonical/witnesses/DLL-001/original_rff_parser_metadata_gettexcellidx.summary.json').read_text())
assert f['fact_id']=='FACT-0365' and f['status']=='PROVEN_DLL'
assert {x['source_id'] for x in f['evidence']}=={'DLL-001'} and w['source_ids']==['DLL-001']
assert len(f['chain_edges'])==1
assert w['private_witness']['committed_to_git'] is False
assert w['original_dll']['sha256']==prev['original_dll']['sha256']
assert w['called_method_il_sha256']==prev['get_tex_cell_idx']['il_sha256']
assert [(x['token'],x['name'],x['call_opcode_offset']) for x in w['method_bodies']]==[('0x06001F0E','LoadFormData',302),('0x06001F12','ParseFormData_RFF',169)]
assert w['method_bodies'][1]['sha256']==prev['original_dll']['parser_il_sha256']
assert len(w['source_windows'])==5 and all(len(x['sha256'])==64 and x['start']<x['end'] for x in w['source_windows'])
assert w['observed_parser_counter']['bgt_target_offset']==193 and w['observed_parser_counter']['fallthrough_offset']==187
assert w['source_field_tokens']=={'texKind':'0x040026C0','cellIdx':'0x040026C1','partsNum':'0x040026CB'}
assert len([x for x in r['families'] if x['fact_id']=='FACT-0365' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0365 original GetTexCellIdx direct consumer and source counter summary PASS')
