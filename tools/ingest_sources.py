#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

CANON_DLL = "9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
VAULT_SHA = "810e9149be0869094ff5dd266afa754745bb708bda648ed0c9e6999c266cf68a"

class IngestError(RuntimeError):
    pass

def sha256(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_members(zf: zipfile.ZipFile):
    out = []
    for info in zf.infolist():
        p = Path(info.filename)
        if p.is_absolute() or ".." in p.parts:
            raise IngestError(f"unsafe ZIP member: {info.filename}")
        out.append({
            "name": info.filename,
            "size": info.file_size,
            "crc32": f"{info.CRC:08x}"
        })
    return out

def read_zip_json(zf, basename):
    matches = [n for n in zf.namelist() if Path(n).name.lower() == basename.lower()]
    if len(matches) != 1:
        raise IngestError(f"expected exactly one {basename}, found {len(matches)}")
    return json.loads(zf.read(matches[0]).decode("utf-8-sig"))

def ingest_dll(path):
    path = Path(path)
    got = sha256(path)
    if got != CANON_DLL:
        raise IngestError(f"DLL hash mismatch: {got}")
    return {"kind":"DLL", "filename":path.name, "sha256":got, "verified":True}

def ingest_vault(path):
    path = Path(path)
    got = sha256(path)
    if got != VAULT_SHA:
        raise IngestError(f"vault hash mismatch: {got}")
    with zipfile.ZipFile(path, "r") as zf:
        members = safe_members(zf)
        bad = zf.testzip()
        if bad is not None:
            raise IngestError(f"vault ZIP CRC failure: {bad}")
    return {"kind":"DECODE_VAULT", "filename":path.name, "sha256":got, "verified":True, "member_count":len(members), "members":members}

def ingest_capture(path, label, require_move_trace=False):
    path = Path(path)
    got = sha256(path)
    with zipfile.ZipFile(path, "r") as zf:
        members = safe_members(zf)
        bad = zf.testzip()
        if bad is not None:
            raise IngestError(f"{label} ZIP CRC failure: {bad}")
        names = {Path(n).name.lower() for n in zf.namelist()}
        required = {"metadata.json", "tick_trace.tsv", "event_trace.tsv"}
        if require_move_trace:
            required.add("move_trace.tsv")
        missing = sorted(required - names)
        if missing:
            raise IngestError(f"{label} missing raw recorder members: {missing}")
        meta = read_zip_json(zf, "metadata.json")
        dll_hash = str(meta.get("assembly_csharp_sha256", "")).lower()
        if dll_hash != CANON_DLL:
            raise IngestError(f"{label} metadata DLL mismatch: {dll_hash or '<blank>'}")
        if meta.get("observational_only") is not True:
            raise IngestError(f"{label} metadata does not declare observational_only=true")
    return {
        "kind":"RAW_RECORDER_CAPTURE",
        "label":label,
        "filename":path.name,
        "sha256":got,
        "verified":True,
        "dll_sha256":CANON_DLL,
        "member_count":len(members),
        "members":members,
        "metadata":meta
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True)
    ap.add_argument("--vault")
    ap.add_argument("--r6")
    ap.add_argument("--r4")
    ap.add_argument("--out", default="source_ingestion_report.json")
    a = ap.parse_args()
    try:
        report = {"schema_version":1, "canonical_dll_sha256":CANON_DLL, "sources":[]}
        report["sources"].append(ingest_dll(a.dll))
        if a.vault:
            report["sources"].append(ingest_vault(a.vault))
        if a.r6:
            report["sources"].append(ingest_capture(a.r6, "R6", require_move_trace=True))
        if a.r4:
            report["sources"].append(ingest_capture(a.r4, "R4", require_move_trace=False))
        out = Path(a.out)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"SOURCE INGESTION PASS -> {out}")
        return 0
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, IngestError) as e:
        print("SOURCE INGESTION FAIL")
        print(str(e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
