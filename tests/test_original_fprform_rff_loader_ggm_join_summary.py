"""FACT-0359 read-only original DLL loader, GGM and original metadata joined source witness."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESMETA-001/original_fprform_rff_ggm_loader_join.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0359-original-fprform-rff-loader-ggm-object-join.json').read_text())
registry=json.loads((R/'canonical/transition_registry.json').read_text())
manifest=json.loads((R/'canonical/source_manifest.json').read_text())
a=w['original_dll'];g=w['original_ggm'];m=w['original_metadata_prefix'];z=w['observed']
assert f['fact_id']=='FACT-0359' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(w['source_ids'])=={x['source_id'] for x in f['evidence']}=={'DLL-001','GGM-001','RESMETA-001'}
assert len(f['chain_edges'])==3
assert a['sha256']=='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
assert a['loader']['method']=='LoadFormData_RFF' and a['loader']['token']=='0x06001F0F'
assert a['loader']['body_bytes']==83 and a['loader']['body_sha256']=='5d2ae2977dfe90a988ef4fffae2933a16eeed22044cd87a1db7ff705cbdf8b23'
assert [(x['start'],x['end']) for x in a['loader']['windows']]==[(0,32),(32,48),(48,67),(67,83)]
assert a['loader']['resource_name_user_string']['text']=='WrestlerAnimation/fprform_rff'
assert a['loader']['instructions']['form_array_length_constant']==37999
assert a['loader']['instructions']['forms_field_token']=='0x040026DD'
assert a['loader']['instructions']['parse_call_token']=='0x06001F12'
assert g['sha256']=='04cf0c7a5ef858ce68ff5b00b7281ded8fc5b4efe84539d26c21799a4044c22c'
assert (g['record_count'],g['entry']['index'],g['entry']['file_id'],g['entry']['path_id'])==(43941,43500,5,22906)
assert g['entry']['record_sha256']=='750737d6592af2a89bd546f629104372fb68ba5c71a74242098a5ed20f2fe975'
assert m['sha256']=='8388d7e2401172e5ee1139f617afeac8a68aaeb64383bc076098a922e45151da'
assert m['object']['objectinfo_row_sha256']=='e045a41429562e93642cf0b0fefcc4c28a60c8308f8e1216a3a87f5d1c0814ca'
assert (m['object']['path_id'],m['object']['class_id'],m['object']['declared_body_bytes'],m['object']['payload_absolute_offset'])==(22906,49,12800024,1970578200)
assert z['original_ggm_index']==43500 and z['original_resources_path_id']==22906 and z['ascii_casefold_name_equal'] is True
for v in (a,g,m):
    assert len([x for x in manifest['sources'] if x['source_id']==v['source_id'] and x['sha256']==v['sha256']])==1
assert len([x for x in registry['families'] if x['fact_id']=='FACT-0359' and x['runtime_eligible'] is False])==1
assert registry['runtime_unlocked'] is False
print('FACT-0359 original loader GGM serialized object metadata triple source witness PASS')
