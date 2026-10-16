"""FACT-0368 source-only nine-folder asset-name routing checkpoint."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/'canonical/witnesses/DLL-001/original_partstex_nine_folder_name_routing.summary.json').read_text())
f=json.loads((ROOT/'canonical/facts/FACT-0368-original-partstex-nine-folder-name-routing.json').read_text())
r=json.loads((ROOT/'canonical/transition_registry.json').read_text())
p=json.loads((ROOT/'canonical/witnesses/DLL-001/original_parts_texture_loading_sprite_creation.summary.json').read_text())
assert f['fact_id']=='FACT-0368' and f['status']=='PROVEN_DLL'
assert s['source_ids']==['DLL-001'] and {x['source_id'] for x in f['evidence']}=={'DLL-001'}
assert len(f['chain_edges'])==1 and s['private_witness']['committed_to_git'] is False
assert s['original_dll']['sha256']==p['original_dll']['sha256']
assert len(s['methods'])==6 and len(s['source_windows'])==8
assert all(len(x['il_sha256'])==64 for x in s['methods'])
assert [x['filename_code'] for x in s['source_mapping']]==['fc','ch','bo','ua','fa','sh','th','ha','fo']
assert [x['folder'] for x in s['source_mapping']]==['P0_FACE','P1_CHEST','P2_BODY','P3_UARM','P4_FARM','P5_SHIN','P6_THIGH','P7_HAND','P8_FOOT']
assert s['base_prefixes']==['s','m','l','d','f','b','k']
assert s['code_sites']['category_substring']=={'start':2,'length':2,'opcode_offset':3}
assert s['code_sites']['filename']['resource_prefix']=='PartsTex/'
assert s['code_sites']['highlight_suffix']=='_h'
assert s['methods'][2]['il_sha256']==p['source_methods'][0]['il_sha256']
assert len([a for a in r['families'] if a['fact_id']=='FACT-0368' and a['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0368 nine original folder/code/source route summary PASS')
