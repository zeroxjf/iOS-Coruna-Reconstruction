# iOS-Coruna-Reconstruction

Clean-room reconstruction of the **Coruna** iOS exploit chain. The browser-stage notes span **iOS 16.2 – 17.2.1**; the documented native chain in this repo is strongest for **iOS 16.3+**.

## Coverage Split

- **iOS 16 path:** `terrorbird` Stage1 on `16.2–16.5.1`, then the older `seedbell` branch on `16.3–16.5.1`
- **iOS 17 path:** `cassowary` Stage1 on `16.6–17.2.1`, plus `seedbell_pre` and the newer `seedbell` branch on `17.0–17.2.1`
- **Shared native path in the notes:** the documented chain includes `Stage3_VariantB.js`, `bootstrap.dylib`, record `0x80000`, record `0x90000`, record `0x90001`, and `TweakLoader`; this standalone repo discusses those artifacts but does not ship most of them
- **Current implementation gap:** the least-finished part is still the per-version native `0x90000` logic, especially on newer firmware

## Chain Overview

```
┌──────────────────────────────┐
│  index.html                  │
│  Fingerprint device/iOS,     │
│  select stage payloads       │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Stage 1 — Browser Primitive │
│                              │
│  "terrorbird" 16.2–16.5.1    │
│  "cassowary"  16.6–17.2.1    │
│                              │
│  JIT/speculation bug         │
│  → JSC heap corruption       │
│  → addrof / fakeobj          │
│  → arb read64/write64        │
│    via WASM-backed views     │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Stage 2 — PAC Bypass        │
│  ("seedbell")                │
│                              │
│  16.x + 17.x branches        │
│  JS r/w → arm64e PAC         │
│  sign/auth/call via          │
│  BreakIterator abuse         │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Stage 3 — Native Loader     │
│                              │
│  Rebuild 0xF00DBEEF record,  │
│  map bootstrap.dylib,        │
│  jump to _process            │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Post-Exploit                │
│                              │
│  bootstrap.dylib             │
│  → orchestrator (0x80000)    │
│  → driver (0x90000)          │
│  → TweakLoader (0xF0000)     │
│  → extract Mach-O            │
│  → patch dyld lib-valid      │
│  → dlopen → next_stage_main  │
└──────────────────────────────┘
```

## Disclaimer

This repository was assembled primarily with Codex GPT-5.4 xhigh across multiple iterative passes — not a single one-shot generation. Each pass refined and cross-checked the previous output against disassembly, decompilation, the original live mirror, the internal exploit-chain writeup, and known chain behavior, but the results are still AI-assisted inferences. There may be mistakes, omissions, or misinterpretations. Verify offsets, structures, control flow, primitives, and behavioral conclusions against the original binaries, firmware images, and live test devices before relying on any part of it.

This standalone repo is a distilled publication, not the original workspace. Some long-form notes cite the original `live-site/` mirror and an internal writeup as provenance; those private inputs were used during reconstruction but are intentionally not included here to avoid redistributing the original chain.

## Scope

The focus here is reconstructing the exploit chain without the original malware packaging and delivery behavior.

Current status:

- strong RE dossier for the chain shape and record formats
- compile-checked clean-room contracts and loader-side helper code
- supporting tooling for payload inspection and Stage3 output rebuilds
- not yet a finished end-to-end clean exploit implementation

## Layout

- [`docs/FULL_RECONSTRUCTION.md`](docs/FULL_RECONSTRUCTION.md)
  - detailed exploit-chain reconstruction notes
- [`docs/CLEAN_ROOM_BLUEPRINT.md`](docs/CLEAN_ROOM_BLUEPRINT.md)
  - clean-room module boundaries and implementation plan
- [`clean-room/README.md`](clean-room/README.md)
  - notes specific to the clean-room source tree
- [`clean-room/include/coruna_contracts.h`](clean-room/include/coruna_contracts.h)
  - recovered ABI and record definitions
- [`clean-room/include/coruna_stage_loader.h`](clean-room/include/coruna_stage_loader.h)
  - loader-side record-store and worker-pack contracts
- [`tools/coruna_payload_tool.py`](tools/coruna_payload_tool.py)
  - helper for payload/record inspection and Stage3 output rebuilds

## Verification

From the repo root:

```sh
clang -std=c11 -Wall -Wextra -Werror -Iclean-room/include -fsyntax-only \
  clean-room/src/coruna_contracts.c \
  clean-room/src/coruna_stage_loader.c

python3 -m py_compile tools/coruna_payload_tool.py
```

These checks catch syntax drift only. They do not validate reconstructed control flow, offsets, record layouts, or behavior against the original artifacts.
