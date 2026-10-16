"""FACT-0363 static original lookup table metadata and initialization summary."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/'canonical/witnesses/DLL-001/original_rff_static_cell_tables_initializer.summary.json').read_text())
f=json.loads((ROOT/'canonical/facts/FACT-0363-original-rff-static-cell-tables-initializer.json').read_text())
r=json.loads((ROOT/'canonical/transition_registry.json').read_text())
p=json.loads((ROOT/'canonical/witnesses/DLL-001/original_rff_parser_metadata_gettexcellidx.summary.json').read_text())
assert f['fact_id']=='FACT-0363' and f['status']=='PROVEN_DLL'
assert {x['source_id'] for x in f['evidence']}==set(w['source_ids'])=={'DLL-001'}
assert len(f['chain_edges'])==1
assert w['witness']['bytes']==23696 and w['witness']['sha256']=='1bb4096dea965f7df0c3a68081f9087ff266f0e138e51572114d928987a53c1d'
assert w['original_dll']['helper_il_sha256']==p['get_tex_cell_idx']['il_sha256']
assert w['original_dll']['parser_il_sha256']==p['original_dll']['parser_il_sha256']
assert w['initializer']['il_bytes']==208 and w['initializer']['sha256']=='2562856d53a75ed59fdb2bc6d6788f03308cad38175f0a38a8331c3a06d0c131'
blocks=w['initializer']['blocks']
assert len(blocks)==9 and [x['size'] for x in blocks]==[42,51,50,51,44,48,74,95,118]
assert sum(x['size'] for x in blocks)==w['initializer']['total_elements']==573
assert all(x['il_start']==i*23 and x['il_end']==(i+1)*23 for i,x in enumerate(blocks))
assert [x['dest_token'] for x in blocks]==[f'0x{0x040026E0+i:08X}' for i in range(9)]
assert blocks[1]['original_data_field_token']==blocks[3]['original_data_field_token']
assert len(w['fields'])==9 and all(x['is_static'] and x['type']=='System.Int32[]' for x in w['fields'])
assert len([x for x in r['families'] if x['fact_id']=='FACT-0363' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0363 original nine static cell tables metadata and .cctor source summary PASS')
