# Raw Source Ingestion

No previous Notion statement, runtime package, candidate ZIP, assembler module or handoff is accepted as canonical evidence.

## Required first-source set

1. `Assembly-CSharp.dll`
   - required SHA-256: `9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6`
   - raw bytes already verified in the current reconstruction session.

2. `FirePro_RETAIL_DECODE_VAULT_v001_2026-09-20.zip`
   - required SHA-256: `810e9149be0869094ff5dd266afa754745bb708bda648ed0c9e6999c266cf68a`
   - raw archive must be supplied again. The checksum file alone is not enough.

3. `2026-09-27_204320.zip`
   - R6 eight-wrestler recorder capture.
   - raw archive must be supplied again.
   - its own metadata must pin the canonical DLL hash before any transition record is accepted.

4. `2026-09-26_123451.zip`
   - older structural capture, optional for the first pass but useful for cross-checking families absent from R6.
   - raw archive must be supplied again before use.

## Ingestion rule

Place raw sources in a local-only directory and run:

```
python tools/ingest_sources.py --dll <Assembly-CSharp.dll> --vault <vault.zip> --r6 <2026-09-27_204320.zip>
```

The tool verifies byte hashes and recorder metadata, rejects unsafe ZIPs, inventories raw members and writes a local JSON report. Raw proprietary files remain outside Git.

A source becomes `canonical_eligible=true` only after raw ingestion succeeds. Derived audits and old summaries never flip that bit.
