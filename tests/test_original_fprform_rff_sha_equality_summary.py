"""FACT-0360 source-only SHA-pinned original bounded probe and matching TextAsset export summary."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESOBJ-003/original_fprform_rff_body_sha_and_embedded_bytes.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0360-original-fprform-rff-object-sha-equality.json').read_text())
manifest=json.loads((R/'canonical/source_manifest.json').read_text())
registry=json.loads((R/'canonical/transition_registry.json').read_text())
prev=json.loads((R/'canonical/witnesses/RESMETA-001/original_fprform_rff_ggm_loader_join.summary.json').read_text())
p=w['user_original_probe_report'];m=w['original_metadata_prefix'];u=w['matching_export'];x=u['textasset_wrapper']
assert f['fact_id']=='FACT-0360' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(w['source_ids'])=={y['source_id'] for y in f['evidence']}=={'RESMETA-001','RESOBJ-003'}
assert len(f['chain_edges'])==2
assert p['bytes']==1070 and p['sha256']=='5722a99cb55b26753f6eb386084d2a297bad78e30950821807b2a2461415abe3'
assert p['original_parent_full_file_sha_rechecked'] is False and p['reported_equal'] is True
assert p['path_id']==prev['original_metadata_prefix']['object']['path_id']==22906
assert p['object_absolute_offset']==prev['original_metadata_prefix']['object']['payload_absolute_offset']==1970578200
assert p['object_bytes']==prev['original_metadata_prefix']['object']['declared_body_bytes']==12800024
assert p['reported_original_object_sha256']==p['reported_previous_uabe_sha256']==u['sha256']=='3d457734faf243a6efabd57756a48c82c1f27cc5a4294c567cc51804afd1ab6d'
assert m['sha256']==prev['original_metadata_prefix']['sha256']
assert m['objectinfo_row_sha256']==prev['original_metadata_prefix']['object']['objectinfo_row_sha256']
assert u['size_bytes']==12800024 and x['name_utf8']=='fprform_rff' and x['name_length']==11
assert x['embedded_data_length']==12800000 and x['embedded_data_start']==20 and x['embedded_data_end_exclusive']==12800020
assert x['embedded_data_sha256']=='ad16142531130b7ff36ead502c490be7ac639159817de45b471039c90a262d41'
assert x['trailing_bytes_hex']=='00000000'
assert w['observed']['source_320_byte_divisibility']==40000 and w['observed']['source_320_byte_interpretation_proven'] is False
assert len([y for y in manifest['sources'] if y['source_id']=='RESOBJ-003' and y['sha256']==u['sha256']])==1
assert len([y for y in registry['families'] if y['fact_id']=='FACT-0360' and y['runtime_eligible'] is False])==1
assert registry['runtime_unlocked'] is False
print('FACT-0360 original bounded SHA probe and independently verified exported TextAsset summary PASS')
