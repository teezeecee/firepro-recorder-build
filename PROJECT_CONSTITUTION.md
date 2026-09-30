# PROJECT CONSTITUTION

This file is the highest project-level authority after the user's explicit instructions. It exists to prevent long-chat drift.

## Non-negotiable objective

Reconstruct Fire Pro Wrestling World retail behaviour and animation/state-transition machinery from copied/decoded retail evidence. Do not replace unknown retail behaviour with plausible behaviour.

## Permanent rules

1. **UNKNOWN MEANS STOP.** Missing ownership, indexing, timing, state, bank, direction, root, lookup or aftermath information blocks promotion.
2. **NO NAME-BASED SEMANTICS.** Enum names, method names, slot labels and filenames are navigation clues, not proof of storage layout or behaviour.
3. **NO INFERENCE BRIDGES.** A chain such as logical slot -> saved field -> skill -> animation must be proven at every edge.
4. **LIVE CAPTURE FIRST WHEN WITNESSED.** If a recorder corpus contains the transition, its exact participant/state/bank/timing/root sequence is mandatory oracle evidence.
5. **DLL EXPLAINS OWNERSHIP/CONTROL FLOW.** Matching DLL evidence must close who calls what, ordering, lookup semantics, state ownership and side effects.
6. **PACKED DATA DEFINES AUTHORED CHOREOGRAPHY.** Forms, banks, timing, flags, offsets and animation payload come from the actual retail resource, not recreated examples.
7. **SYNTHETIC TESTS CANNOT PROMOTE FACTS.** They only regression-test facts already closed from retail evidence.
8. **NOTION IS NEVER CANONICAL.** Existing and future Notion material is historical/project-management context only. It cannot satisfy provenance.
9. **OLD RUNTIMES ARE QUARANTINED.** No R-series, v0.xx, assembler module, viewer or candidate implementation is automatically trusted. Code may be reused only after its behaviour re-earns provenance in this repository.
10. **ONE WORKING TREE, NOT ZIP-PER-THOUGHT.** Development happens in the canonical Git branch/tree. User packages are milestone snapshots only, not the development model.
11. **ATOMIC PROMOTION.** A behaviour is canonical only when its provenance record, tests and code are in the same Git commit and the guardrail passes.
12. **NO STRATEGY DRIFT.** The active milestone may not be changed by the assistant for convenience. A strategic change requires explicit user approval and a committed milestone change.
13. **RUNTIME CONSTRUCTION IS CURRENTLY LOCKED.** First consolidate rules, transition grammar, lookup/data layout and capture oracles. Runtime code is blocked until the milestone explicitly unlocks it.
14. **FAIL CLOSED.** Unsupported behaviour produces a named blocker, never a substitute animation, guessed index, approximated timing or silently altered rule.
15. **PROPRIETARY RAW SOURCES STAY LOCAL.** GitHub stores hashes, manifests, extracted factual records and tools, not the retail DLL/assets themselves.

Changing this constitution is itself a strategic change and must be visible in Git history.
