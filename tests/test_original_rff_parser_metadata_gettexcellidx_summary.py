"""FACT-0362 static original 23-token metadata and 412-byte GetTexCellIdx source routing summary."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=json.loads((R/'canonical/witnesses/DLL-001/original_rff_parser_metadata_gettexcellidx.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0362-original-rff-parser-metadata-texcell-routing.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
p=json.loads((R/'canonical/witnesses/DLL-001/original_fprform_rff_parser_il_stride.summary.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
assert f['fact_id']=='FACT-0362' and f['status']=='PROVEN_DLL'
assert {x['source_id'] for x in f['evidence']}==set(s['source_ids'])=={'DLL-001'}
assert len(f['chain_edges'])==1
assert s['witness']['bytes']==15404 and s['witness']['sha256']=='57162e6cf907b6f3747b03c5c910080319f4a944f0195ce4555940a7152013c3'
assert s['metadata_resolution']['requested']==s['metadata_resolution']['resolved']==23
assert s['metadata_resolution']['unresolved']==0 and len(s['metadata_resolution']['fields'])==15
assert len(s['metadata_resolution']['types'])==5 and len(s['metadata_resolution']['constructors'])==2
assert s['original_dll']['sha256']==p['original_parser']['original_dll_sha256']==m['canonical_dll_sha256']
assert s['original_dll']['parser_il_sha256']==p['original_parser']['parser_il_sha256']
h=s['get_tex_cell_idx']
assert h['token']=='0x06001F18' and h['il_bytes']==412
assert h['il_sha256']=='fa82ffc9e97c358e5e770ced915611b73550d15c5ea39fd7713ed1a726e3f5ec'
assert h['windows'][0]['start']==0 and h['windows'][-1]['end']==412
assert all(h['windows'][i]['end']==h['windows'][i+1]['start'] for i in range(4))
assert len(h['bands'])==9 and h['bands'][0]['char_idx_start']==1 and h['bands'][-1]['char_idx_end']==573
assert [v['tex_kind_value'] for v in h['bands']]==list(range(9))
assert all(h['bands'][i]['char_idx_end']+1==h['bands'][i+1]['char_idx_start'] for i in range(8))
assert h['negative_case']=={'char_idx_max':0,'tex_kind_value':-1,'cell_idx_value':-1}
assert h['other_case']['char_idx_min']==574 and h['other_case']['tex_kind_value']==9
assert [v['char_idx'] for v in h['special_cases']]==[621,622,623,624]
assert [v['tex_kind_value'] for v in h['special_cases']]==[10,11,12,13]
assert h['original_lookup_array_contents_proven'] is False
assert len([x for x in r['families'] if x['fact_id']=='FACT-0362' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0362 original 23-token metadata and GetTexCellIdx 412-byte routing summary PASS')
