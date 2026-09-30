#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_WORDS = {"ASSUMED", "INFERRED", "PLAUSIBLE", "SYNTHETIC_ONLY", "NOTION_ONLY", "NAME_BASED", "UNPROVEN"}
ALLOWED_STATUSES = {"PROVEN_DLL", "OBSERVED_RAW_CAPTURE", "PROVEN_PACKED_DATA", "CORROBORATED_MULTI_SOURCE"}

class GuardrailError(RuntimeError):
    pass

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def validate_fact(fact, sources):
    missing = [k for k in ("fact_id", "claim", "status", "evidence", "chain_edges") if k not in fact]
    if missing:
        raise GuardrailError(f"{fact.get('fact_id','<unknown>')}: missing fields {missing}")
    status = str(fact["status"]).upper()
    if status not in ALLOWED_STATUSES:
        raise GuardrailError(f"{fact['fact_id']}: status {status} is not promotable")
    blob = json.dumps(fact, sort_keys=True).upper()
    hit = sorted(w for w in FORBIDDEN_WORDS if w in blob)
    if hit:
        raise GuardrailError(f"{fact['fact_id']}: forbidden provenance markers present: {hit}")
    if not isinstance(fact["evidence"], list) or not fact["evidence"]:
        raise GuardrailError(f"{fact['fact_id']}: no evidence")
    for ev in fact["evidence"]:
        sid = ev.get("source_id")
        if sid not in sources:
            raise GuardrailError(f"{fact['fact_id']}: unknown source_id {sid}")
        src = sources[sid]
        if not src.get("canonical_eligible", False):
            raise GuardrailError(f"{fact['fact_id']}: source {sid} is not canonical-eligible ({src.get('availability')})")
        if not ev.get("locator"):
            raise GuardrailError(f"{fact['fact_id']}: evidence from {sid} lacks reproducible locator")
    for i, edge in enumerate(fact["chain_edges"]):
        for k in ("from", "to", "evidence"):
            if not edge.get(k):
                raise GuardrailError(f"{fact['fact_id']}: chain edge {i} missing {k}")
        if not isinstance(edge["evidence"], list) or not edge["evidence"]:
            raise GuardrailError(f"{fact['fact_id']}: chain edge {i} has no evidence")
        for ev in edge["evidence"]:
            sid = ev.get("source_id")
            if sid not in sources or not sources[sid].get("canonical_eligible", False):
                raise GuardrailError(f"{fact['fact_id']}: chain edge {i} uses unavailable/untrusted source {sid}")
            if not ev.get("locator"):
                raise GuardrailError(f"{fact['fact_id']}: chain edge {i} evidence lacks locator")

def validate_repo(root=ROOT):
    milestone = load_json(root / "MILESTONE.json")
    manifest = load_json(root / "canonical" / "source_manifest.json")
    sources = {s["source_id"]: s for s in manifest["sources"]}

    dll = sources.get("DLL-001")
    if not dll or dll.get("sha256") != manifest.get("canonical_dll_sha256") or not dll.get("canonical_eligible"):
        raise GuardrailError("canonical DLL identity is not closed")

    if milestone.get("runtime_locked"):
        forbidden_runtime = []
        for p in root.rglob("*"):
            if p.is_file() and any(part.lower() in {"runtime", "viewer", "candidate"} for part in p.relative_to(root).parts[:-1]):
                forbidden_runtime.append(str(p.relative_to(root)))
        if forbidden_runtime:
            raise GuardrailError("runtime construction is locked but runtime/viewer/candidate files exist: " + ", ".join(forbidden_runtime[:10]))

    facts = sorted((root / "canonical" / "facts").glob("*.json"))
    for p in facts:
        validate_fact(load_json(p), sources)
    return len(facts)

def main():
    try:
        n = validate_repo()
    except GuardrailError as e:
        print("PROVE_NO_ASSUMPTIONS: FAIL")
        print(str(e))
        return 1
    print(f"PROVE_NO_ASSUMPTIONS: PASS ({n} canonical fact records)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
