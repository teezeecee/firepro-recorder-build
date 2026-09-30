#!/usr/bin/env python3
import argparse
import csv
import hashlib
import io
import json
import zipfile
from collections import Counter
from pathlib import Path

R6_SHA256 = "93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA256 = "79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
MOVE_SHA256 = "f424f69f1d357bc2635b38b5b01b279c904c5e0b266e24da26dd1a94c35839ee"
SOURCE_ID = "CAP-R6-001"
SHARED_FIELDS = [
    "AnmHostPlayer","BasicSkillID","HostSkillID","HostSkillNameEN",
    "ResolvedSkillID","ResolvedSkillNameEN","ResolvedSkillNameJP","ResolvedSkillSource",
    "SkillSlotID","anmType","args","bank","method","owner_label",
    "owner_player_id","owner_slot","phase","tick","weaponIdx",
]

class PairingError(RuntimeError):
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
        raise PairingError(f"expected exactly one {basename}, found {len(hits)}")
    return hits[0]

def prove(r6_zip, out_summary):
    r6_zip = Path(r6_zip)
    if sha256_path(r6_zip) != R6_SHA256:
        raise PairingError("R6 archive SHA-256 mismatch")

    with zipfile.ZipFile(r6_zip, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise PairingError(f"R6 ZIP CRC failure: {bad}")

        event_name = one_member(zf, "event_trace.tsv")
        move_name = one_member(zf, "move_trace.tsv")
        with zf.open(event_name) as f:
            event_sha = sha256_stream(f)
        with zf.open(move_name) as f:
            move_sha = sha256_stream(f)
        if event_sha != EVENT_SHA256:
            raise PairingError(f"event_trace SHA-256 mismatch: {event_sha}")
        if move_sha != MOVE_SHA256:
            raise PairingError(f"move_trace SHA-256 mismatch: {move_sha}")

        event_info = zf.getinfo(event_name)
        move_info = zf.getinfo(move_name)
        form_rows = {}
        event_methods = Counter()
        event_form_count = 0
        event_data_rows = 0

        with zf.open(event_name) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""), delimiter="\t")
            required = {"tick","seq","type",*SHARED_FIELDS}
            missing = sorted(required - set(reader.fieldnames or []))
            if missing:
                raise PairingError(f"event_trace missing required columns: {missing}")
            for event_data_rows, row in enumerate(reader, start=1):
                if row["type"] != "FormAnimator":
                    continue
                event_form_count += 1
                event_methods[row["method"]] += 1
                key = (row["tick"], int(row["seq"]))
                if key in form_rows:
                    raise PairingError(f"duplicate event FormAnimator tick/seq key: {key}")
                form_rows[key] = (event_data_rows + 1, row)

        pairing_digest = hashlib.sha256()
        move_methods = Counter()
        move_data_rows = 0
        matched = 0
        missing_partner = 0
        mismatch_rows = 0
        seq_delta_counts = Counter()
        first_pair = None
        last_pair = None

        with zf.open(move_name) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""), delimiter="\t")
            required = {"tick","seq",*SHARED_FIELDS}
            missing = sorted(required - set(reader.fieldnames or []))
            if missing:
                raise PairingError(f"move_trace missing required columns: {missing}")
            for move_data_rows, row in enumerate(reader, start=1):
                move_methods[row["method"]] += 1
                move_seq = int(row["seq"])
                partner = form_rows.get((row["tick"], move_seq - 1))
                if partner is None:
                    missing_partner += 1
                    continue
                event_line, event_row = partner
                move_line = move_data_rows + 1
                delta = move_seq - int(event_row["seq"])
                seq_delta_counts[delta] += 1
                if any(event_row[field] != row[field] for field in SHARED_FIELDS):
                    mismatch_rows += 1
                    continue
                matched += 1
                record = [
                    event_line, move_line, row["tick"], int(event_row["seq"]), move_seq,
                    *[row[field] for field in SHARED_FIELDS],
                ]
                pairing_digest.update(
                    (json.dumps(record, separators=(",",":"), ensure_ascii=False) + "\n").encode("utf-8")
                )
                loc = {
                    "event_line": event_line, "move_line": move_line, "tick": int(row["tick"]),
                    "event_seq": int(event_row["seq"]), "move_seq": move_seq, "method": row["method"],
                }
                if first_pair is None:
                    first_pair = loc
                last_pair = loc

    if event_form_count != move_data_rows:
        raise PairingError(f"row-count mismatch: {event_form_count} vs {move_data_rows}")
    if missing_partner or mismatch_rows or matched != move_data_rows:
        raise PairingError(
            f"pairing mismatch: matched={matched} missing={missing_partner} mismatched={mismatch_rows}"
        )
    if event_methods != move_methods:
        raise PairingError("raw method-string count mismatch between paired row sets")

    summary = {
        "schema_version": 1,
        "dataset_id": "R6_EVENT_MOVE_PAIRING_V1",
        "source_id": SOURCE_ID,
        "definition": (
            "For each move_trace data row, locate the event_trace row at the same tick with event seq exactly one lower; "
            "require the event row's recorded type string to equal FormAnimator and require all listed shared fields to be identical raw strings. "
            "No semantic meaning is assigned to type, method, skill, animation, bank, or state labels."
        ),
        "source_archive_sha256": R6_SHA256,
        "members": {
            "event_trace": {
                "name": event_name, "sha256": EVENT_SHA256, "crc32": f"{event_info.CRC:08x}",
                "size_bytes": event_info.file_size, "data_rows": event_data_rows,
            },
            "move_trace": {
                "name": move_name, "sha256": MOVE_SHA256, "crc32": f"{move_info.CRC:08x}",
                "size_bytes": move_info.file_size, "data_rows": move_data_rows,
            },
        },
        "shared_fields": SHARED_FIELDS,
        "result": {
            "event_rows_with_type_FormAnimator": event_form_count,
            "move_rows": move_data_rows,
            "matched_pairs": matched,
            "missing_partner_rows": missing_partner,
            "shared_field_mismatch_rows": mismatch_rows,
            "seq_delta_counts": {str(k): v for k, v in sorted(seq_delta_counts.items())},
            "method_counts": dict(sorted(move_methods.items())),
            "pairing_digest_algorithm": "sha256 over UTF-8 compact-JSON lines [event_line,move_line,tick,event_seq,move_seq,<19 shared move-row field strings in shared_fields order>]",
            "pairing_digest_sha256": pairing_digest.hexdigest(),
            "first_pair": first_pair,
            "last_pair": last_pair,
        },
        "promotion_scope": "RAW_OBSERVATION_ONLY",
        "semantic_claims": [],
        "limits": [
            "This establishes only an exact raw-record relationship between two R6 trace members.",
            "The recorded strings FormAnimator and method/skill/animation labels are not treated as semantic proof.",
            "No gameplay behavior, control-flow ownership, authored choreography, timing rule, damage rule, or aftermath rule is promoted by this dataset.",
        ],
    }
    out_summary = Path(out_summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--r6", required=True)
    ap.add_argument("--out-summary", required=True)
    args = ap.parse_args()
    try:
        s = prove(args.r6, args.out_summary)
        print(f"R6 EVENT/MOVE PAIRING PASS: {s['result']['matched_pairs']} pairs, digest={s['result']['pairing_digest_sha256']}")
        return 0
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, PairingError, ValueError, KeyError) as e:
        print("R6 EVENT/MOVE PAIRING FAIL")
        print(str(e))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
