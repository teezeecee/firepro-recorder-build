"""FACT-0374 source-only public regression; private source bytes stay in separate vault."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical/witnesses/TEXTSAMPLE-001/original_four_crn_native_to_bcn_exact_rgba.summary.json").read_text())
f=json.loads((ROOT/"canonical/facts/FACT-0374-original-crn-native-bcn-four-sample-rgba.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
m=json.loads((ROOT/"canonical/source_manifest.json").read_text())
assert f["fact_id"]=="FACT-0374" and f["status"]=="PROVEN_PACKED_DATA"
sources={x["source_id"]:x for x in m["sources"]}
assert sources["TEXTSAMPLE-001"]["canonical_eligible"] is True
assert sources["TEXTSAMPLE-001"]["sha256"]==s["original_samples_archive"]["sha256"]
assert s["parent_fact"]=="FACT-0373" and s["independent_verification"]["result_status"]=="SOURCE_TRANSCODE_PASS"
assert s["independent_verification"]["independent_rgba_decoder_crosscheck"] is True
assert len(s["original_samples"])==4
assert [x["path_id"] for x in s["original_samples"]]==[390,1407,6308,15464]
for x in s["original_samples"]:
    fmt=x["block_format"]
    assert fmt in ("BC1","BC3")
    n=((x["width"]+3)//4)*((x["height"]+3)//4)*(8 if fmt=="BC1" else 16)
    assert x["bc_bytes"]==n
    assert x["decoded_rgba_bytes"]==x["width"]*x["height"]*4
    assert x["independent_decoder_exact_full_rgba_match"] is True
    for field in ("original_crn_sha256","bc_sha256","decoded_rgba_sha256"):
        assert len(x[field])==64 and all(c in "0123456789abcdef" for c in x[field])
assert len([x for x in r["families"] if x["fact_id"]=="FACT-0374" and x["runtime_eligible"] is False])==1
assert s["runtime_eligible"] is False and r["runtime_unlocked"] is False
print("FACT-0374 four native Crunch source decodes, BC hashes and independent full RGBA parity summaries PASS")
