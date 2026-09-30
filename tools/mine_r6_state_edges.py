#!/usr/bin/env python3
import argparse
import csv
import hashlib
import io
import json
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

R6_SHA256 = "93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
CANON_DLL_SHA256 = "9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
SOURCE_ID = "CAP-R6-001"
TICK_BASENAME = "tick_trace.tsv"
META_BASENAME = "metadata.json"

class MineError(RuntimeError):
    pass

def sha256_stream(f):
    h = hashlib.sha256()
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
    return h.hexdigest()

def sha256_path(path):
    with Path(path).open("rb") as f:
        return sha256_stream(f)

def one_member(zf, basename):
    hits = [n for n in zf.namelist() if Path(n).name.lower() == basename.lower()]
    if len(hits) != 1:
        raise MineError(f"expected exactly one {basename}, found {len(hits)}")
    return hits[0]

def mine(r6_zip, out_index, out_summary):
    r6_zip = Path(r6_zip)
    got = sha256_path(r6_zip)
    if got != R6_SHA256:
        raise MineError(f"R6 archive hash mismatch: {got}")

    with zipfile.ZipFile(r6_zip, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise MineError(f"R6 ZIP CRC failure: {bad}")

        meta_name = one_member(zf, META_BASENAME)
        tick_name = one_member(zf, TICK_BASENAME)
        meta = json.loads(zf.read(meta_name).decode("utf-8-sig"))
        if str(meta.get("assembly_csharp_sha256", "")).lower() != CANON_DLL_SHA256:
            raise MineError("R6 metadata DLL hash does not match canonical DLL")
        if meta.get("observational_only") is not True:
            raise MineError("R6 metadata does not declare observational_only=true")

        with zf.open(tick_name) as raw:
            tick_sha256 = sha256_stream(raw)
        tick_info = zf.getinfo(tick_name)

        last = {}
        edge_counts = Counter()
        player_counts = Counter()
        occurrences = defaultdict(list)
        witness_count = 0
        data_rows = 0

        with zf.open(tick_name) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""), delimiter="\t")
            required = {"tick","seq","player_slot","player_id","State"}
            missing = sorted(required - set(reader.fieldnames or []))
            if missing:
                raise MineError(f"tick_trace missing required columns: {missing}")

            for data_rows, row in enumerate(reader, start=1):
                line = data_rows + 1
                slot = row["player_slot"]
                prev = last.get(slot)
                if prev is not None and prev["State"] != row["State"]:
                    witness_count += 1
                    edge = (prev["State"], row["State"])
                    edge_counts[edge] += 1
                    player_counts[slot] += 1
                    occurrences[edge].append([
                        int(slot),
                        prev["line"], line,
                        int(prev["tick"]), int(row["tick"]),
                        int(prev["seq"]), int(row["seq"]),
                    ])
                last[slot] = {
                    "line": line,
                    "tick": row["tick"],
                    "seq": row["seq"],
                    "State": row["State"],
                }

    index = {
        "schema_version": 1,
        "dataset_id": "R6_TICK_STATE_EDGES_V1",
        "source_id": SOURCE_ID,
        "definition": "An occurrence is emitted when the recorder-emitted State string for one stable player_slot differs between two consecutive sampled tick_trace rows for that same slot. State strings are opaque recorded values; no gameplay meaning is inferred.",
        "occurrence_fields": ["player_slot","before_line","after_line","before_tick","after_tick","before_seq","after_seq"],
        "edges": [
            {
                "from_State": a,
                "to_State": b,
                "count": edge_counts[(a,b)],
                "occurrences": occurrences[(a,b)],
            }
            for a,b in sorted(edge_counts, key=lambda e:(-edge_counts[e], e[0], e[1]))
        ],
    }
    out_index = Path(out_index)
    out_index.parent.mkdir(parents=True, exist_ok=True)
    out_index.write_text(json.dumps(index, separators=(",",":"), ensure_ascii=False) + "\n", encoding="utf-8")
    index_sha256 = sha256_path(out_index)

    summary = {
        "schema_version": 1,
        "dataset_id": "R6_TICK_STATE_EDGES_V1",
        "source_id": SOURCE_ID,
        "source_archive_sha256": R6_SHA256,
        "canonical_dll_sha256": CANON_DLL_SHA256,
        "source_member": {
            "name": tick_name,
            "sha256": tick_sha256,
            "crc32": f"{tick_info.CRC:08x}",
            "size_bytes": tick_info.file_size,
            "header_line": 1,
            "data_rows": data_rows,
        },
        "definition": index["definition"],
        "index_file": {
            "path": out_index.name,
            "sha256": index_sha256,
            "format": "compact JSON",
            "occurrence_fields": index["occurrence_fields"],
            "record_count": witness_count,
        },
        "distinct_state_edge_count": len(edge_counts),
        "edge_counts": [
            {"from_State": a, "to_State": b, "count": n}
            for (a,b), n in sorted(edge_counts.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1]))
        ],
        "player_transition_counts": [
            {"player_slot": int(slot), "count": n}
            for slot,n in sorted(player_counts.items(), key=lambda kv:int(kv[0]))
        ],
        "promotion_scope": "RAW_OBSERVATION_ONLY",
        "semantic_claims": [],
        "next_required_evidence": [
            "Matching DLL control-flow/ownership evidence for any semantic interpretation of an edge.",
            "Packed retail choreography/data evidence before animation meaning, bank meaning, timing meaning, or aftermath meaning is promoted."
        ]
    }
    out_summary = Path(out_summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--r6", required=True)
    ap.add_argument("--out-index", required=True)
    ap.add_argument("--out-summary", required=True)
    a = ap.parse_args()
    try:
        s = mine(a.r6, a.out_index, a.out_summary)
        print(f"R6 STATE EDGE MINING PASS: {s['index_file']['record_count']} witnesses / {s['distinct_state_edge_count']} distinct edges")
        return 0
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, MineError, ValueError, KeyError) as e:
        print("R6 STATE EDGE MINING FAIL")
        print(str(e))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
