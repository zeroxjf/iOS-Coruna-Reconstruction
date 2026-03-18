# iOS-Coruna-Reconstruction

> **Disclaimer:** This repo was built iteratively with **Codex GPT-5.4 xhigh** and **Claude Opus 4.6 max**, cross-checked against IDA Pro decompilation, the original live mirror, and firmware artifacts. Not a single one-shot generation — each pass refined the previous output against disassembly and known chain behavior. There will be mistakes. Verify everything against the actual binaries before relying on it. The original exploit binaries, JS stages, and IPSW firmware are intentionally excluded to avoid redistributing the chain.

Clean-room reconstruction of the **Coruna** iOS exploit chain (iOS 16.2 – 17.2.1), reverse-engineered from the live mirror using IDA Pro.

Coruna is a full-chain browser-to-kernel exploit delivered via WebKit. It chains a JSC type-confusion, an `Intl.Segmenter`/BreakIterator PAC bypass, and a custom IOGPU/AGX + IOSurface kernel exploit into persistent code execution — then cleans up after itself.

## Chain at a Glance

```
index.html ─── fingerprint device, select stages
     │
     ▼
 Stage 1 ───── WebKit JSC type-confusion
                "terrorbird" (16.2–16.5.1) / "cassowary" (16.6–17.2.1)
                → addrof / fakeobj / arb r/w via WASM-backed views
     │
     ▼
 Stage 2 ───── PAC bypass ("seedbell")
                corrupt Intl.Segmenter / ICU BreakIterator
                → pacda / pacia / autda / autia / indirect call
     │
     ▼
 Stage 3 ───── native loader
                rebuild 0xF00DBEEF container from manifest
                map bootstrap.dylib, jump to _process
     │
     ▼
 bootstrap ─── select payload hash, fetch via JS/native bridge
     │
     ├─ 0x80000  orchestrator: resolve _driver, launch worker
     ├─ 0x90000  kernel exploit: IOSurface + IOGPU/AGX + PPL
     │           → sandbox/AMFI/developer-mode policy patches
     ├─ 0xA0000  anti-forensics: delete crash reports, diagnostics,
     │           WebKit caches, analytics aggregates
     └─ 0xF0000  TweakLoader: extract embedded Mach-O, bypass
                 dyld lib-validation, dlopen → next_stage_main
```

## What's Recovered

| Area | Status |
|---|---|
| Chain shape and stage selection | Fully traced through both iOS 16 and 17 paths |
| Stage 1 (JSC primitives) | Mechanics documented for both `terrorbird` and `cassowary` |
| Stage 2 (PAC bypass) | Gadget chains and corruption path documented for all `seedbell` branches |
| Stage 3 (native loader) | Container format, JS/native bridge protocol, bootstrap mapping all recovered |
| `bootstrap.dylib` | `_process`, callback registry, anti-analysis checks, selector/manifest resolution, LZMA decompression |
| `0x80000` orchestrator | Full dispatch flow through `_start` → `_startl` → worker → `sub_7410` → `_startr` across two variants |
| `0x90000` kernel exploit | Vtable, IOSurface pivot, policy patching, selector contracts, terminal helper families |
| `0xA0000` cleanup | Fully decompiled — targets, helper functions, entry contract |
| `0xF0000` TweakLoader | Exports, dyld bypass, embedded `__SBTweak` extraction, `next_stage_main` contract |
| `prefix32` sideband | Traced to native consumption in `sub_6BA0` |
| Record contracts | 14 record IDs mapped including 3 runtime-synthesized (`0x10000`, `0x30000`, `0x40000`) |
| Clean-room C contracts | Compile-checked headers and validation helpers |

**Remaining gap:** source-equivalent reconstruction of the per-version `0x90000` kernel exploit logic.

## Layout

```
docs/
  FULL_RECONSTRUCTION.md    full chain reconstruction notes
  CLEAN_ROOM_BLUEPRINT.md   module contracts and implementation plan
clean-room/
  include/                  recovered ABI: record IDs, structs, vtable layouts
  src/                      validation helpers, record-store logic
tools/
  coruna_payload_tool.py    payload inspection, container rebuilds, section extraction
```

## Quick Verification

```sh
clang -std=c11 -Wall -Wextra -Werror -Iclean-room/include -fsyntax-only \
  clean-room/src/coruna_contracts.c \
  clean-room/src/coruna_stage_loader.c

python3 -m py_compile tools/coruna_payload_tool.py
```

