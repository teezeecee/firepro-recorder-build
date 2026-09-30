#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("guard", ROOT / "tools" / "prove_no_assumptions.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

manifest = guard.load_json(ROOT / "canonical" / "source_manifest.json")
sources = {s["source_id"]: s for s in manifest["sources"]}
good = guard.load_json(ROOT / "canonical" / "facts" / "FACT-0001-matching-dll.json")


def must_fail(label, fact, expected):
    try:
        guard.validate_fact(fact, sources)
    except guard.GuardrailError as e:
        if expected not in str(e):
            raise AssertionError(f"{label}: wrong failure: {e}")
        print(f"PASS blocked {label}: {e}")
        return
    raise AssertionError(f"{label}: guardrail incorrectly allowed it")


guard.validate_fact(good, sources)
print("PASS accepts proven DLL identity")

good_r6 = {
    "fact_id": "TEST-R6-RAW-SOURCE",
    "claim": "The freshly verified R6 raw capture is admissible as observational evidence.",
    "status": "OBSERVED_RAW_CAPTURE",
    "evidence": [{"source_id": "CAP-R6-001", "locator": "tick_trace.tsv line 2"}],
    "chain_edges": []
}
guard.validate_fact(good_r6, sources)
print("PASS accepts freshly verified R6 raw source")

bad = copy.deepcopy(good)
bad["fact_id"] = "BAD-ASSUMPTION"
bad["status"] = "ASSUMED"
must_fail("assumed fact", bad, "not promotable")

bad = copy.deepcopy(good)
bad["fact_id"] = "BAD-MISSING-RAW"
bad["status"] = "PROVEN_PACKED_DATA"
bad["evidence"] = [{"source_id": "VAULT-001", "locator": "whole archive"}]
must_fail("unavailable raw source", bad, "not canonical-eligible")

bad = copy.deepcopy(good)
bad["fact_id"] = "BAD-NAME-BRIDGE"
bad["claim"] = "Logical slot24 probably maps to saved skillSlot[24]"
bad["status"] = "PROVEN_DLL"
bad["evidence"] = [{"source_id": "DLL-001", "locator": "method name only"}]
bad["chain_edges"] = []
bad["note"] = "PLAUSIBLE from name"
must_fail("name-based bridge", bad, "forbidden provenance markers")

bad = copy.deepcopy(good)
bad["fact_id"] = "BAD-EDGE"
bad["chain_edges"] = [{"from": "logical slot24", "to": "serialized skillSlot[24]", "evidence": []}]
must_fail("semantic bridge without evidence", bad, "missing evidence")

print("GUARDRAIL SELFTEST: PASS")
