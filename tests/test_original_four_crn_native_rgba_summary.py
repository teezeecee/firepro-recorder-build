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
expected_hashes={
    390:("2b55d3322b898d05325c66aa14ed20b026c917a9fde6a5bf04a4e35f80a4ccf5","1f5c5d240ae9247d580a4ba03c0859c2affb938bf952ed836380282400b3e19a"),
    1407:("7256181b9f9bc3f6cebc023aad65d76d9ae166c0258bff2a8871117483ea8119","e5585be8a71910c1aa8a20f236e36c515a33ff49a8836b45fb4fad6f230eccd9"),
    6308:("ca7bc85370a132196d5f62d71c06c78882bb54da5ec0a8164b398e7be1d44e99","9ff264df30464c677063e4afacc6b3e7ed90d53c724e4ccceac418bc44b4372e"),
    15464:("fe0665dd5ca35fca3bc7ed540ce75a9add287a4001a1e1704e4d9fb5a982c309","2f6aeb23095771c7965dbe81f58aec255541c4efbf62cc8da225fdf05ca9401a")
}
for x in s["original_samples"]:
    assert (x["bc_sha256"],x["decoded_rgba_sha256"])==expected_hashes[x["path_id"]]
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
