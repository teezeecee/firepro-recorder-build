#!/usr/bin/env python3
"""FACT-0326: prove the original Unity globalgamemanagers external-file reference table."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WITNESS = ROOT / "canonical/witnesses/GGM-001/external_fileid_mappings.summary.json"

def ck(ok, description):
    if not ok:
        raise AssertionError(description)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def cstr(data, p):
    end = data.index(b"\0", p)
    return data[p:end].decode("utf-8"), end + 1

def prove(path, w):
    raw = Path(path).read_bytes()
    src = w["original_file"]
    ck((len(raw), sha(raw)) == (src["bytes"], src["sha256"]), "original source SHA and byte length")
    ck(struct.unpack_from(">IIIII", raw, 0) == (1379, 5002540, 17, 4096, 0), "Unity original header")
    p = 20
    version, p = cstr(raw, p)
    ck(version == src["unity_version"], "original Unity version")
    platform, type_tree, count = struct.unpack_from("<iBI", raw, p)
    ck((platform, type_tree, count) == (5, 0, src["type_count"] == 20 and 20), "original platform and type count")
    p += 9
    for _ in range(count):
        _, removed, script_index = struct.unpack_from("<iBh", raw, p)
        ck(removed == 0 and script_index == -1, "original type row")
        p += 23
    obj_count = struct.unpack_from("<I", raw, p)[0]
    ck(obj_count == src["object_count"] == 20, "original object count")
    p = (p + 4 + 3) & ~3
    for _ in range(obj_count):
        path_id, offset, size, type_index = struct.unpack_from("<qIII", raw, p)
        ck(path_id > 0 and type_index < count and src["data_offset"] + offset + size <= len(raw), "object table bounds")
        p += 20
    tbl = w["external_reference_table"]
    ck(p == tbl["preceding_zero_u32_offset"] == 904, "external preamble offset")
    ck(struct.unpack_from("<I", raw, p)[0] == 0, "original preamble zero")
    p += 4
    ck(p == tbl["count_field_offset"] == 908, "external count offset")
    n = struct.unpack_from("<I", raw, p)[0]
    ck(n == tbl["count"] == len(w["references"]) == 11, "external row count")
    p += 4
    ck(p == tbl["first_row_offset"], "external first row offset")
    for expected in w["references"]:
        ck(p == expected["start_offset"], "exact original row start")
        asset_path, p = cstr(raw, p)
        guid = raw[p:p+16].hex()
        ck(len(guid) == 32, "GUID width")
        p += 16
        kind = struct.unpack_from("<i", raw, p)[0]
        p += 4
        target_path, p = cstr(raw, p)
        ck(expected["file_id"] == w["references"].index(expected) + 1, "external fileID ordinal")
        ck((p, asset_path, guid, kind, target_path) == (
            expected["end_offset"], expected["asset_path"], expected["guid_hex"],
            expected["type"], expected["path"]), "exact original row bytes/fields")
    ck(p == tbl["rows_end_offset"] == 1398, "all rows parsed exactly")
    ck(sha(raw[tbl["count_field_offset"]:p]) == tbl["raw_rows_with_count_sha256"], "exact original row count+body SHA")
    ck(raw[p] == tbl["trailing_metadata_byte"] == 0, "terminal metadata zero")
    ck(p + 1 == tbl["metadata_end_offset"] == 20 + src["metadata_size"], "full original metadata boundary")
    ck(sha(raw[tbl["count_field_offset"]:p+1]) == tbl["raw_rows_count_and_trailer_sha256"], "full original table SHA")
    ck(w["references"][2]["path"] == w["graphics_settings_join"]["mapped_external_path"], "builtin shader external route")
    ck(w["references"][0]["path"] == w["graphics_settings_join"]["sprite_default_material_mapped_path"], "material external route")
    return {"fact": "FACT-0326", "source_proof": "PASS", "external_refs": 11, "metadata_end": p+1, "runtime_eligible": False}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--globalgamemanagers", required=True)
    args = ap.parse_args()
    try:
        w = json.loads(WITNESS.read_text(encoding="utf-8"))
        ck(w["dataset_id"] == "UNITY_GGM_EXTERNAL_PPTR_FILEID_TABLE_V1", "witness identity")
        print(json.dumps(prove(args.globalgamemanagers, w), sort_keys=True))
        print("PROVE_GLOBALGAMEMANAGERS_EXTERNAL_REFS: PASS")
        return 0
    except Exception as exc:
        print("PROVE_GLOBALGAMEMANAGERS_EXTERNAL_REFS: FAIL", str(exc))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
