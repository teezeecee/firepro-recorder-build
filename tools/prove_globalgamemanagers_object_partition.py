#!/usr/bin/env python3
"""FACT-0341: byte-exact original Unity globalgamemanagers ObjectInfo payload census.

Read-only: requires the user's own original Unity game file. No proprietary
source bytes are checked into this project and no runtime fields are guessed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WITNESS = ROOT / 'canonical/witnesses/GGM-001/objectinfo_20_complete_payload_partition.summary.json'


def digest(b):
    return hashlib.sha256(b).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def prove(original, witness):
    blob = Path(original).read_bytes()
    identity = witness['original_file']
    metadata = witness['metadata']
    payload = witness['payload']
    require((len(blob), digest(blob)) == (identity['bytes'], identity['sha256']), 'original full-file SHA')
    require(struct.unpack_from('>IIIII', blob, 0) == (1379, len(blob), 17, 4096, 0), 'Unity header fields')
    pos = 20
    nul = blob.index(b'\0', pos)
    require(blob[pos:nul] == b'5.6.5p3', 'Unity version')
    pos = nul + 1
    platform, type_tree, type_count = struct.unpack_from('<iBI', blob, pos)
    pos += 9
    require((platform, type_tree, type_count) == (5, 0, 20), 'Unity metadata types')
    classes = []
    for _ in range(type_count):
        class_id, deleted, script_type = struct.unpack_from('<iBh', blob, pos)
        pos += 23
        require((deleted, script_type) == (0, -1), 'original 23-byte serialized class record')
        classes.append(class_id)
    require(classes == metadata['class_id_order'], 'exact 20 class IDs')
    object_count = struct.unpack_from('<I', blob, pos)[0]
    pos = (pos + 4 + 7) & ~7
    require((object_count, pos) == (20, metadata['object_info_start']), 'original ObjectInfo count/start')
    found = []
    for i in range(object_count):
        pid, relative, size, type_index = struct.unpack_from('<qIII', blob, pos)
        pos += 20
        require(type_index < len(classes), 'object type index within table')
        absolute = identity['data_offset'] + relative
        require(absolute + size <= len(blob), 'ObjectInfo bounds')
        found.append(dict(object_index=i, path_id=pid, type_index=type_index,
                          class_id=classes[type_index], relative_offset=relative,
                          absolute_offset=absolute, byte_size=size,
                          body_sha256=digest(blob[absolute:absolute+size])))
    require(pos == metadata['object_info_end'], 'ObjectInfo exact end')
    require(digest(blob[504:904]) == metadata['object_info_sha256'], 'raw ObjectInfo table hash')
    require(found == witness['objects'], 'all 20 exact original records, lengths, body hashes')
    require(digest(blob[20:1399]) == metadata['metadata_sha256'], 'metadata SHA')
    require((metadata['metadata_end'], metadata['post_metadata_zero_padding_start'],
             metadata['post_metadata_zero_padding_end']) == (1399, 1399, 4096), 'metadata/data delimiter')
    require(blob[1399:4096] == bytes(4096-1399), 'all 2697 metadata padding bytes zero')
    require(digest(blob[1399:4096]) == metadata['post_metadata_padding_sha256'], 'padding hash')
    require((payload['start'], payload['end'], payload['length']) == (4096, len(blob), len(blob)-4096),
            'payload covers end of file')
    require(digest(blob[4096:]) == payload['sha256'], 'original entire payload SHA')
    previous = 4096
    concatenated = []
    gaps = []
    padded = []
    for entry in sorted(found, key=lambda e:(e['absolute_offset'], e['object_index'])):
        start = entry['absolute_offset']
        require(start >= previous, 'no overlap or unordered object boundary')
        if start > previous:
            gap = blob[previous:start]
            require(gap == bytes(len(gap)), 'all inter-object alignment bytes must be zero')
            gaps.append(dict(start=previous, end=start, bytes=len(gap), hex=gap.hex()))
            padded.append(gap)
        ending = start + entry['byte_size']
        concatenated.append(blob[start:ending])
        previous = ending
    require(previous == len(blob), 'all original payload accounted to last byte')
    require(gaps == witness['alignment_gaps'], 'exact alignment gap offsets and bytes')
    require(digest(b''.join(concatenated)) == payload['object_bodies_in_order_sha256'],
            'aggregate of 20 body windows')
    require(digest(b''.join(padded)) == payload['gap_bytes_in_order_sha256'],
            'aggregate of 9 padding windows')
    require(sum(len(part) for part in concatenated) == payload['sum_object_bytes'] == 4998401,
            'total object body bytes')
    require(sum(len(part) for part in padded) == payload['sum_gap_bytes'] == 43,
            'total zero alignment bytes')
    require(len(gaps) == payload['gap_count'] == 9, 'nine original padding windows')
    require(len(found) == payload['object_body_count'] == 20, 'twenty original ObjectInfo')
    empty = [e['path_id'] for e in found if e['byte_size'] == 0]
    require(empty == payload['empty_path_ids'] == [9, 15, 21], 'three zero-body object IDs')
    require(sum(e['byte_size'] > 0 for e in found) == payload['nonempty_object_count'] == 17,
            'seventeen nonempty original object bodies')
    require(sum(e['byte_size'] == 0 for e in found) == payload['empty_object_count'] == 3,
            'three original zero-body entries')
    require(payload['length'] == payload['sum_object_bytes']+payload['sum_gap_bytes'],
            'full payload partition identity')
    require(witness['dataset_id'] == 'UNITY_GGM_20_OBJECTINFO_COMPLETE_PAYLOAD_PARTITION_V1',
            'registry witness ID')
    return {'fact':'FACT-0341', 'original_file_sha':'PASS', 'original_object_info_entries':20,
            'complete_payload_bytes':payload['length'], 'original_object_bodies_bytes':4998401,
            'alignment_zeros':43, 'unclassified_payload_bytes':0, 'runtime_eligible':False}


if __name__ == '__main__':
    arg = argparse.ArgumentParser()
    arg.add_argument('--globalgamemanagers', required=True)
    args = arg.parse_args()
    witness = json.loads(WITNESS.read_text(encoding='utf-8'))
    print(json.dumps(prove(args.globalgamemanagers, witness), sort_keys=True))
    print('PROVE_GGM_FULL_OBJECTINFO_PARTITION: PASS')
