# Retail asset recovery inventory (noncanonical checkpoint) — 2026-10-09

> **Status:** planning and original-file observations only. **Not FACT-0264**, not a retroactive claim that the lost archive was decoded, and **not** permission to build a runtime or viewer.

This checkpoint inventories what can be recovered from the user's still-installed **Fire Pro Wrestling World** retail files, and what the **Gated Fire Pro Restart** still has to source-prove. It accompanies [`retail_asset_recovery_inventory_2026-10-09.json`](retail_asset_recovery_inventory_2026-10-09.json). The authoritative existing baseline is **263 consecutively numbered canonical facts, 262 unique registry family IDs**, branch `canonical-retail-rebuild-v1` at `949323da086cf6d0242b4f5efce02ad3c539871d` before this documentation change.

## Missing September 20 vault: distinguish archive from sources

The unlocated historical `FirePro_RETAIL_DECODE_VAULT_v001_2026-09-20.zip` has expected SHA-256 `810e9149be0869094ff5dd266afa754745bb708bda648ed0c9e6999c266cf68a` from its old checksum, **but we do not have its raw archive or complete manifest**. Therefore **its exact former contents cannot be asserted**. It was intended to preserve retail decode material. Do not treat the loss of this derivative ZIP as loss of retail resources. In particular, freshly supplied original Unity `TextAsset` exports already recover some underlying bytes.

Do not call the old reference-assembler checkpoint an equivalent vault. Previous assembler/audit verdicts were explicitly quarantined at Gated Fire Pro Restart; each candidate is a locator to be retested, never canonical provenance by itself.

## Original source observations (export files stay local; never commit proprietary bytes)

| Evidence | Independent checks | Meaning / boundary |
|---|---|---|
| User-provided UABEA `fprwaza-resources.assets-22804.dat` | 1,511,048 bytes; SHA-256 `7bba8a12d2cd835969a982e757fd986897b1c3ac076e777c8cca2aacd11b997d`; reported TextAsset Path ID **22804** | `m_Script` payload 1,511,028 bytes, SHA-256 `2d8dd223214b0c45e3e3b3dcc092dbba4bec2cd2ba1c71940bd05d9a519bcdc1`. Exact first 31,008 payload bytes form 3,876 little-endian (offset, length) pairs. **3,054 nonempty**, **822 empty**. Nonempty ranges are contiguous, bounded, start with `RS`, and their internal size values equal indexed lengths. These are *slots*, **not proven 3,054 distinct named moves**. |
| User-provided UABEA `fpw_6172-resources.assets-21353.dat` | 1,716 bytes; SHA-256 `de13a6efdff9727d63542134096b056f2c680c606b7703e82b4fd6839fc30cf1`; Path ID **21353** | Distinct 1,696-byte `RS` payload; no exact match to any populated `fprwaza` entry. Relationship to stock/DLC banks remains open. |
| Original DLL | 8,171,008 bytes, original matching SHA-256 `9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6` | `SkillDataMan.LoadPackedSkillData`, `_loadPackedSkillData`, `ParseRSFData` and related names are parser investigation targets. Any detail of the loader/decoder must be proved from exact DLL bytes before canonical promotion. |
| User-provided `FIREPRO_REFERENCE_ASSEMBLER_v001(3).zip` | 14,565,474 bytes; SHA-256 `7fa5da3cf0a17e2d35dce7d7b5faf7b997b0254f047ae462a63c6b9528976281`; 2,604 ZIP entries; CRC check passes | Contains **69** historical raw TextAsset files, including `PartsInfoList`, `PartsFilterList`, `SkillInfo`, `SkillParam`, `SkillParam_Reversal`, `PresetWrestlerList`, `SampleCostumeList`, `WrestlerVoiceList`, `ThemeMusicList`, **46 `wcos_000–045`** and **9 `rcos_000–008`**. Contains **no raw `fprwaza` export**. Historical data only, not yet source-verified in the restart. |
| Retail Unity containers observed through UABEA / Windows Explorer | `resources.assets`, companion resource streams, `sharedassets*.assets`, `Managed` and other original installed data under `E:\Programs E\SteamLibrary\steamapps\common\Fire Prowrestling World\FireProWrestlingW_Data` | Presence observed, but **the complete parent `resources.assets` file has not itself been locally SHA-256 authenticated**. Two exported sample hashes establish those samples, not a whole-installation hash. |

This document records no original retail binary payload and does not execute quarantined assembler tools.

## What is still needed to complete the asset side?

| Category | Current status | Evidence still required |
|---|---|---|
| Base move/choreography data | **Packed export recovered; semantics still open** | Replay retail packed-loader and RSF data parser; attach move identity and bank/frame/timing/position/participant relationships to source-backed fields. |
| Additional and DLC moves | **Sample `fpw_*` recovered, broad inventory pending** | Find all installed `fpw_*` / DLC sources and independently map their animation records. |
| Wrestler visual parts | **Original Unity containers located** | Source-backed Sprite/Texture2D rectangles, centres/pivots, part identity, palette, nine `partsScale` relationships, limb layering, blood and complete animated pose assembly. Historic 96×96/64×64 and 1,350/1,350 results must **not** be promoted from old test reports alone. |
| Wrestler costume/presets | **Old raw TextAssets present, not revalidated** | Re-identify retail catalogue, filters, `wcos`, `rcos`, wrestler/costume and installed DLC linking. |
| Weapons/objects/effects | **Historical references only** | Locate and prove object/sprite/texture and effects resource lookups, rendering and applicable breakage art (including `bktable`). |
| Voices/SFX | **Historical voice-ID lookup only** | Locate actual needed AudioClip/asset bundle payloads, retail IDs and triggers. Optional/background music is not a mandatory project extraction target. |
| Rings, aprons and arenas | **Installed resource containers exist, independent asset mapping pending** | Verify required ropes, posts, ring/apron visuals, cage and deathmatch hazard resources, and visual/physical interfaces needed for the future 2D modules. |
| Included creation GUI / installed parts | **Historical descriptions, not verified asset inventory** | Source-backed UI sprites/data for Create Wrestler, Create Ref, other included screens and preinstalled Parts Craft content. |

**Do not conflate asset recovery with application fidelity.** At minimum, one move must be traced from source-identified record through banks, frames, participant/root offsets, images, sort/pivots and timings, and compared with a retail oracle. This is an evidence target, **not authorization to make a viewer now**.

## Controlled recovery order, not ZIP-per-test

1. Reconcile GitHub canonical head, open PRs, latest merge, Actions and Notion before any fact work. Keep historical PRs #127/#32 separate.
2. Trace the **exact original** `SkillDataMan` loader/parser bytes for `fprwaza` and the `RS` records. Prove source mapping; distinguish this from the separately stored `fpw_*` payloads.
3. Verify retail parent-container provenance and resource routes from **read-only** installed Unity files. Preserve immutable SHA hashes/metadata; leave bulky proprietary source bytes outside public GitHub.
4. Complete one original stock animation's entire source chain, including art, bank ownership, offsets, timing, facing and layering, without relying on old assembler animation assumptions.
5. Expand verified installed-resource routing to DLC, wrestler parts/presets, weapon and visual effects, audio/voices, ring/environment and included creation UI. Use a **read-only** lazy resource provider only after the milestone authorizes runtime infrastructure.
6. Promote genuinely new source facts individually with replayable witness/verifier/test, unique family IDs and the established `prove-no-assumptions` pre- and post-merge PR gates. This docs-only inventory **does not increment FACT-0263**.
7. Keep `MILESTONE.json` `SOURCE_CONSOLIDATION_V1` and `runtime_locked: true` until the user explicitly approves a milestone transition. No speculative renderer, no new program ZIPs.

## Important distinction

Missing **old vault ZIP**: unresolved archive inventory and unavailable bytes.

Recovered **original move data**: the user has newly supplied original `fprwaza` and a sample `fpw_*` UABEA export, with independent hashes and structural checks.

Missing **complete verified asset interpretation**: parser semantics, full original art/audio/catalogue routes and verified bank/frame rendering remain open. Thus the missing vault is no longer a reason to deny that original sources exist, but **runtime construction remains locked for the separate approved strategy gate**.

See [PROJECT_CONSTITUTION.md](../PROJECT_CONSTITUTION.md) and [MILESTONE.json](../MILESTONE.json); this checkpoint is deliberately additive documentation, not a silent strategy change.

## Original parser prefix and bounded early-exit audit (2026-10-09)
Original DLL-001 MethodDef 0x06005257 checks each signed index offset against input byte-array length and exits the indexed first loop when the offset is **not less than** the length, even before its literal maximum index 4188. In SHA-pinned, parent-unverified UABEA export fprwaza-resources.assets-22804.dat, m_Script starts at serialized export offset 16 and is exactly 1,511,028 bytes. There are 3,876 original 8-byte index pairs: entries 0–3874 precede payload end, including 3,054 populated RS records and 821 zero-length entries. Final entry 3875 is (1,511,028, 0), so **if these export bytes are loaded through the DLL method**, the original control flow terminates at 3875. The previous 822 empty entry count includes this terminator. Do not add synthetic slots or confuse the upper bound with required file count.
Parser MethodDef 0x0600525F (1735 IL bytes, SHA 09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae) starts by optionally retrieving SkillInfo, constructs SkillData, skips ten bytes from its input byte offset, and stores unsigned bytes at relative +10 and +11 in retail fields reversalSkillType and reversalRateType. FACT-0266 proves **these two fields only**, not the remaining 1640 IL bytes or authored choreography. The parent Unity resources.assets SHA and actual Resources.Load binding are still unverified, so the export check remains a conditional, noncanonical observation. No asset or game binary was committed.

### FACT-0266 cursor correction audit (2026-10-09)
The first version of FACT-0266 incorrectly reported the first two indexed byte positions as `arg2+11` and `arg2+12`. The **original DLL raw bytes have not changed**. After ten explicit `ldloc.2; ldc.i4.1; add; stloc.2` increments from original argument2, the parser's `dup` pattern leaves the previous cursor value on the evaluation stack for `ldelem.u1` while updating local2 for the *next* read. Accordingly original `SkillData.reversalSkillType` consumes byte at `arg2+10` and `SkillData.reversalRateType` consumes byte at `arg2+11`; next byte read starts at `arg2+12`. This correction is recorded transparently as a separate GitHub PR against FACT-0266 and its original-byte verifier. All preexisting SHA evidence, source metadata, original bytes, index stop, and 266-fact count remain unchanged. The added test fails on +11/+12 to prevent recurrence.
