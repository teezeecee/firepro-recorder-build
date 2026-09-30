#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import io
import json
import zipfile
import zlib
from collections import Counter
from pathlib import Path

R6_SHA256 = "93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
CANON_DLL_SHA256 = "9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
SOURCE_ID = "CAP-R6-001"
TICK_BASENAME = "tick_trace.tsv"
META_BASENAME = "metadata.json"
MAGIC = b"R6SA1"

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

def put_varint(out, n):
    if n < 0:
        raise MineError("negative varint")
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return

def encode_after_lines(after_lines):
    raw = bytearray(MAGIC)
    put_varint(raw, len(after_lines))
    prev = 0
    for line in after_lines:
        if line <= prev:
            raise MineError("after-line witnesses are not strictly increasing")
        put_varint(raw, line - prev)
        prev = line
    raw = bytes(raw)
    artifact = base64.b64encode(zlib.compress(raw, 9)) + b"\n"
    return raw, artifact

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
        after_lines = []
        data_rows = 0

        with zf.open(tick_name) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""), delimiter="\t")
            required = {"tick", "seq", "player_slot", "player_id", "State"}
            missing = sorted(required - set(reader.fieldnames or []))
            if missing:
                raise MineError(f"tick_trace missing required columns: {missing}")

            for data_rows, row in enumerate(reader, start=1):
                line = data_rows + 1
                slot = row["player_slot"]
                state = row["State"]
                prev = last.get(slot)
                if prev is not None and prev["State"] != state:
                    after_lines.append(line)
                    edge_counts[(prev["State"], state)] += 1
                    player_counts[slot] += 1
                last[slot] = {"line": line, "State": state}

    decoded, artifact = encode_after_lines(after_lines)
    out_index = Path(out_index)
    out_index.parent.mkdir(parents=True, exist_ok=True)
    out_index.write_bytes(artifact)

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
        "definition": (
            "An occurrence is emitted when the recorder-emitted State string for one stable "
            "player_slot differs between two consecutive sampled tick_trace rows for that same "
            "slot. The stored witness is the current raw line number; its paired before-line is "
            "the immediately previous raw row for that player_slot. State strings are opaque "
            "recorded values; no gameplay meaning is inferred."
        ),
        "index_file": {
            "path": out_index.name,
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "decoded_binary_sha256": hashlib.sha256(decoded).hexdigest(),
            "format": "base64(zlib(varint-after-line-index))",
            "magic": MAGIC.decode("ascii"),
            "record_count": len(after_lines),
            "reconstruction_rule": (
                "Decode strictly increasing after-line numbers. For each after-line, read "
                "player_slot from that raw tick_trace line; before-line is the immediately "
                "previous tick_trace data row previously seen for the same player_slot."
            ),
        },
        "distinct_state_edge_count": len(edge_counts),
        "edge_counts": [
            {"from_State": a, "to_State": b, "count": n}
            for (a, b), n in sorted(edge_counts.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1]))
        ],
        "player_transition_counts": [
            {"player_slot": int(slot), "count": n}
            for slot, n in sorted(player_counts.items(), key=lambda kv: int(kv[0]))
        ],
        "promotion_scope": "RAW_OBSERVATION_ONLY",
        "semantic_claims": [],
        "next_required_evidence": [
            "Matching DLL control-flow/ownership evidence for any semantic interpretation of an edge.",
            "Packed retail choreography/data evidence before animation meaning, bank meaning, timing meaning, or aftermath meaning is promoted."
        ],
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
        print(
            "R6 STATE EDGE MINING PASS: "
            f"{s['index_file']['record_count']} witnesses / "
            f"{s['distinct_state_edge_count']} distinct edges"
        )
        return 0
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, MineError, ValueError, KeyError) as e:
        print("R6 STATE EDGE MINING FAIL")
        print(str(e))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
