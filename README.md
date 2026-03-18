# iOS-Coruna-Reconstruction

> **Disclaimer:** This repo was built iteratively with **Codex GPT-5.3-codex xhigh**, **Codex GPT-5.4 xhigh**, and **Claude Opus 4.6 max**, cross-checked against IDA Pro decompilation, the original live mirror, and firmware artifacts. Not a single one-shot generation — each pass refined the previous output against disassembly and known chain behavior. There will be mistakes. Verify everything against the actual binaries before relying on it. The original exploit binaries, JS stages, and IPSW firmware are intentionally excluded to avoid redistributing the chain.

Reverse-engineering reconstruction of the **Coruna** iOS exploit kit, analyzed from the live mirror using IDA Pro. **This is a research analysis — not a working exploit or jailbreak tool.** Based on [Duy Tran](https://github.com/khanhduytran0)'s [coruna](https://github.com/khanhduytran0/coruna) repo (malware-stripped binaries), with the live-site mirror hosted by [34306](https://github.com/34306) and [Nick Chan](https://github.com/asdfugil).

The full Coruna kit ([documented by Google TAG](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)) contains 5 full exploit chains and 23 exploits spanning **iOS 13.0 – 17.2.1**. It combines multiple WebKit RCEs (type confusion, UAF, integer overflow, bounds check bypass), PAC bypasses, sandbox escapes, and kernel exploits across 5 chains to achieve persistent code execution on targeted iOS versions.

### Exploit Chain Map

<details>
<summary>Click to expand — per-version CVE/chain breakdown with dead zones</summary>

The kit uses different exploit chains for different iOS sub-ranges — **no single chain works across the entire 13.0–17.2.1 span**. A full chain needs a WebKit RCE + kernel exploit both unpatched. Codenames are from the kit's internal naming.

| iOS window | WebKit RCE | Kernel | Status |
|---|---|---|---|
| **17.0 – 17.2.1** | `cassowary` · CVE-2024-23222 | Sparrow · CVE-2024-23225 + Rocket · CVE-2024-23296 | WebKit fixed 17.3 |
| **16.6 – 16.7.4** | `cassowary` · CVE-2024-23222 | Parallax · CVE-2023-41974 (16.6–16.7) then CVE-2024-23225/23296 (16.7.1+) | WebKit fixed 16.7.5 |
| **16.7.5** | — | CVE-2024-23225 still open | **Dead — WebKit patched, no RCE** |
| **16.4 – 16.5.1** | `terrorbird` · CVE-2023-43000 | Parallax · CVE-2023-41974 | WebKit fixed 16.6 |
| **16.2 – 16.3.1** | `terrorbird` · CVE-2023-43000 | CVE-2023-32434 + IronLoader · CVE-2023-32409 (sandbox escape) | IronLoader fixed 16.5 |
| **15.6 – 16.1.2** | `bluebird` · CVE unconfirmed | Photon · CVE-2023-32434 (through 15.7.6) / Gallium · CVE-2023-38606 (fallback) | bluebird CVE not publicly mapped |
| **15.2 – 15.5.x** | `jacurutu` · CVE-2022-48503 | Photon · CVE-2023-32434 | WebKit fixed 15.6 |
| **14.5 – 15.1.1** | `buffout` · CVE-2021-30952 | Photon · CVE-2023-32434 | WebKit fixed 15.2; Photon starts 14.5 |
| **14.2 – 14.4** | `buffout` · CVE-2021-30952 | — | **Gap — Neutron patched, Photon starts 14.5** |
| **13.0 – 14.1** | `buffout` · CVE-2021-30952 | Neutron · CVE-2020-27932 + Dynamo · CVE-2020-27950 | Both patched 14.2 |

**Dead on iOS >= 17.3** (WebKit patched) / **>= 17.4** (kernel patched). CVE associations from the [Google TAG report](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit) and [Hacker News](https://thehackernews.com/2026/03/coruna-ios-exploit-kit-uses-23-exploits.html); Google TAG notes some may be revised. Target ranges reflect where the kit deploys each exploit (version-specific offsets), which may be narrower than the CVE's full vulnerable range.

</details>

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
     ├─ 0x80000  dispatch layer: resolve _driver, launch worker
     ├─ 0x90000  kernel exploit: IOSurface + IOGPU/AGX + PPL
     │           → sandbox/AMFI/developer-mode policy patches
     ├─ 0xA0000  cleanup module: delete crash reports, diagnostics,
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
| `bootstrap.dylib` | `_process`, callback registry, environment checks, selector/manifest resolution, LZMA decompression |
| `0x80000` dispatch layer | Full dispatch flow through `_start` → `_startl` → worker → `sub_7410` → `_startr` across two variants |
| `0x90000` kernel exploit | Full exploit loop: IOSurface kaddr leak via `kIOSurfaceMemoryRegion`, kernel object scan + corruption trigger, 3 primitive tiers, 3 state-inheritance paths (shared mem / voucher mailbox / fileport-smuggled fstat), kread/kwrite 6-tier backend, AMFI/sandbox patching, 40+ command selectors |
| `0xA0000` cleanup | Fully decompiled — targets, helper functions, entry contract |
| `0xF0000` TweakLoader | Exports, dyld bypass, embedded `__SBTweak` extraction, `next_stage_main` contract |
| `prefix32` sideband | Traced to native consumption in `sub_6BA0` |
| Record contracts | 14 record IDs mapped including 3 runtime-synthesized (`0x10000`, `0x30000`, `0x40000`) |
| Clean-room C contracts | Compile-checked headers and validation helpers |

**Vulnerability class identified:** IOSurface/IOGPU info leak → pmap permission escalation (PPL bypass). No classic memory corruption — the primitive is built from IOKit external method info disclosure, controlled surface memory mapping, and pmap permission flag writes on existing kernel objects.


---

## Sources

Based on IDA Pro analysis of:

- `live-site/index.html`, `Stage1_*.js`, `Stage2_*.js`, `Stage3_VariantB.js`
- `live-site/payloads/bootstrap.dylib` and `entry*.dylib` / `entry*.bin` across 20 payload sets (19 entry-based containers + 1 raw passthrough set)
- `live-site/TweakLoader/.theos/obj/arm64*/TweakLoader.dylib`
- `EXPLOIT_CHAIN_WRITEUP.md` (internal provenance)
- 17.0.3 IPSW-derived dyld and XNU artifacts

These `live-site/*` references are provenance inputs from the private research mirror; the publication keeps only clean-room outputs and documentation.

## End-to-End Shape

1. `index.html` fingerprints the device, chooses Stage1/Stage2/Stage3, initializes `platformModule.platformState`.
2. Stage1 gets a JS arbitrary read/write primitive.
3. Stage2 converts the JS primitive into PAC-aware `sign/auth/call` primitives on arm64e.
4. Stage3 rebuilds a `0xF00DBEEF` record container from `payloads/manifest.json`, maps `bootstrap.dylib`, jumps to `_process`.
5. `bootstrap.dylib` runs environment checks, spins up the background worker, uses the JS/native shared buffer to request a payload bundle by hash.
6. `0x80000` resolves `_driver` from `0x90000`, obtains a vtable-backed driver object, launches the worker thread.
7. Worker invokes `_startsc` from `0xA0000` (anti-forensics cleanup), then dispatches `_startr`.
8. `0x90000` builds the kernel R/W primitive via IOSurface/IOGPU info leak + pmap permission escalation, patches AMFI/sandbox policy.
9. `0xF0000` (`TweakLoader`) extracts embedded `__SBTweak` Mach-O, patches dyld lib-validation, `dlopen`s it, calls `next_stage_main`.

## Module Split

The chain cleanly decomposes into these modules:

1. `stage1_primitive.js`
   Produces a browser memory primitive with:
   - `addrof`
   - `fakeobj`
   - `read64` / `write64`
   - `read32`
   - `readByte`
   - `readString`
   - `getDataPointer`
   - `getBackingStore`
   - `getJITCodePointer`
   - alloc helpers

   Backend variants:
   - `terrorbird` for `16.2–16.5.1`
   - `cassowary` for `16.6–17.2.1`

2. `stage2_pac.js`
   Consumes the Stage1 primitive and produces:
   - `pacia`
   - `pacda`
   - `autia`
   - `autda`
   - PAC-aware indirect call helpers

   Backend variants:
   - older `seedbell` branch for `16.3–16.5.1`
   - `seedbell_pre` plus newer `seedbell` branch for `17.0–17.2.1`

3. `stage3_loader.js`
   Consumes the Stage2 call primitive and handles:
   - payload manifest fetch
   - `entry2_type0x0f.dylib` rewrite to local `TweakLoader.dylib`
   - `0xF00DBEEF` container rebuild
   - shared-buffer request/response service
   - bootstrap image map and `_process` invocation

4. `bootstrap_loader.c`
   Owns:
   - record registry setup
   - environment gating
   - selector resolution
   - shared-buffer bridge
   - `0x80000` activation

5. `record_0x80000.c`
   Orchestrator module:
   - resolve `_driver` from `0x90000`
   - obtain driver object
   - activate `_startl`
   - load `0xF0000`

6. `record_0x90000.c`
   Kernel primitive / policy-patching service object:
   - init state
   - primitive build
   - policy patch paths
   - teardown

7. `record_0x90001.c`
   Auxiliary bootstrap helper driver:
   - create helper session
   - dispatch bootstrap helper commands
   - tear helper session down

8. `record_0x50000.bin`
   Raw arm64 helper loader:
   - publish internal callback pointers
   - provide direct syscall veneers
   - parse/load FAT and Mach-O payloads in memory

9. `record_0xF0000.c`
   Loader wrapper:
   - export `_last` or `_end`
   - extract embedded Mach-O
   - patch dyld lib-validation
   - `dlopen("/tmp/actual.dylib")`
   - call `next_stage_main`

10. `sbtweak.m`
   Visible post-exploit payload:
   - SpringBoard/lockscreen swizzles
   - overlay install/remove/frontmost maintenance


## Stable Stage Contracts

### Stage1 Output Contract

```js
{
  addrof(obj) -> u64,
  fakeobj(addr) -> object,
  read64(addr) -> u64,
  write64(addr, value),
  read32(addr) -> u32,
  readByte(addr) -> u8,
  readString(addr) -> string,
  getDataPointer(obj) -> u64,
  getBackingStore(typedArrayOrArrayBuffer) -> u64,
  getJITCodePointer(func) -> u64,
  allocCString(str) -> u64,
  allocZeroBuffer(size) -> u64
}
```

That contract is common to both `terrorbird` and `cassowary`. The corruption strategy differs, but the caller-facing primitive is intentionally unified.

### Stage2 Output Contract

```js
{
  pacia(ptr, modifier) -> u64,
  pacda(ptr, modifier) -> u64,
  autia(ptr, modifier) -> u64,
  autda(ptr, modifier) -> u64,
  callSigned(fn, x0, x1, x2, x3, ...) -> u64
}
```

Both `seedbell` branches use a corrupted `Intl.Segmenter` / ICU `BreakIterator` to reach this surface.

### Stage3 Container Contract

```c
struct ContainerHeader {
    uint32_t magic;   // 0xF00DBEEF
    uint32_t count;
};

struct ContainerEntry {
    uint32_t f1;          // logical record id
    uint32_t f2;          // observed 3 in modern sets
    uint32_t data_offset;
    uint32_t size;        // actual fetched byte count, not manifest advisory size
};
```

`f1` is the real record contract:

- `0x70000`
- `0x70005`
- `0x50000`
- `0x80000`
- `0x90000`
- `0x90001`
- `0xF0000`


## Shared Buffer Contract

Recovered from `bootstrap.dylib:sub_987C` and `Stage3_VariantB.js`.

```c
struct SharedBridge {
    volatile uint32_t opcode;
    uint8_t bytes[];
};
```

Observed request/response behavior:

- Native request without secondary string:
  - copy request string to `bytes + 0x0`
  - set `opcode = 1`
- Native request with secondary string:
  - copy primary string to `bytes + 0x0`
  - copy secondary string to `bytes + 0x7ffffc`
  - set `opcode = 7`
- JS success response:
  - set `opcode = 3`
  - write `payload_size` to `bytes + 0x0`
  - copy payload bytes to `bytes + 0x4`
- JS failure/negative response:
  - set `opcode = 4`

The native side busy-waits for `opcode` to become `3` or `4`, then copies the 32-bit size from `bytes + 0x0` and payload bytes from `bytes + 0x4`.

Those offsets are relative to `bytes[]`. The full shared buffer also has a leading 32-bit opcode field, so the equivalent whole-buffer offsets are `+0x4`, `+0x8`, and `+0x800000`.


---

## Stage1: Reconstructed Browser Primitive

Both Stage1 branches converge on the same caller-facing primitive. The main difference is how each browser bug corrupts JSC state before the final WASM-backed memory contract is installed.

### `terrorbird` on iOS 16.2-16.5.1

`terrorbird` is the getter-timed JIT/speculation branch.

Important mechanics:

- It builds two WASM instances plus an object-array side channel (`es`, `ss`, `os`) and keeps both WASM-backed views alive as the stable anchor for later memory operations.
- It heap-shapes aggressively: JSON spray, large `ArrayBuffer` spray, and a long megamorphic dispatcher warmup so the JIT commits to the expected array/object path.
- The trigger object `s` has getters on indices `3` and `8`. One getter returns a far-out array element, the other truncates the backing array length during the JIT-specialized path.
- The final trigger is `s.length = 9; i.u(b, i, s);` so the spread/apply path hits those getters in the middle of optimized array handling.
- The warmed helper functions then reinterpret double-array/object-array slots as each other:
  - pointer encoding into doubles
  - synthetic length read
  - 64-bit read/write through temporarily redirected array headers
- The version-specific callback walks the corrupted graph into JSC runtime structures using `platformState.versionFlags`, rewires the right fields, and stores the final state words into the WASM primitive instance.

Final Stage1 surface:

- `addrof`
- `fakeobj`
- `read64` / `write64`
- `read32`
- `readByte`
- `readString`
- `getDataPointer`
- `getBackingStore`
- `getJITCodePointer`
- `allocCString`
- `allocZeroBuffer`

Important anchors:

- `addrof`: `Stage1_16.2_16.5.1_terrorbird.js:67`
- `fakeobj`: `Stage1_16.2_16.5.1_terrorbird.js:132`
- helper training: `:942`, `:956`, `:965`, `:974`
- exploit trigger: `:914-1006`
- post-trigger harvesting and state install: `:1020-1024`

### `cassowary` on iOS 16.6-17.2.1

`cassowary` reaches the same output surface through a different corruption path.

Important mechanics:

- `tt[...]` is the versioned offset table. `et()` mutates it for 17.0, 17.1, and 17.2.
- `pm.init()` drives a long structure/branch confusion over similarly shaped objects created through `Reflect.construct`, deletes `r.p2` at the critical boundary, and flips one hot path from one object layout to another during JIT optimization.
- `pm.wo()` converts that corruption into three raw cell primitives:
  - object address
  - 64-bit read
  - pointer/raw-double write
- `pm.Ao()` wraps the raw cell primitives into reusable memory operations.
- `$()` then rebinds fresh WASM instances into the same contract that `terrorbird` exposes.
- `q()` runs in a Worker, performs a delayed stabilization pass, scans for a fixed 64-bit pattern near the corrupted tables, and rewrites a small pointer table to make the primitive reliable on 16.6-17.2.1.
- `ht()` finishes on the main thread by using recursive spread to pull the five final state words back out and install `platformState.exploitPrimitive`.

Important anchors:

- version table: `Stage1_16.6_17.2.1_cassowary.js:73-116`
- raw AAR/AAW materialization: `:819-821`
- reusable memory API: `:829-890`
- WASM rebinding: `:912-959`
- worker repair: `:965-1023`
- final primitive install: `:1050-1083`

## Stage2: Reconstructed PAC Bypass

Stage2 is likewise split between an older and newer branch, but both routes still end at the same arm64e PAC-aware sign/auth/call surface.

### 16.3-16.5.1 `seedbell`

Stage2 targets `Intl.Segmenter` and the embedded ICU `BreakIterator`.

Important mechanics:

- It gets the iterator object address from Stage1, then walks to:
  - inline storage
  - `BreakIterator`
  - backing store
  - state
  - internal data
  - delegate/vtable
- The layout constants live in `segmenterOffsets`.
- Gadget discovery is dynamic:
  - `_xmlSAX2GetPublicId` in `libxml2.2.dylib`
  - `_dlfcn_globallookup` in `ActionKit`
  - `_autohinter_iterator_begin` / `_autohinter_iterator_end` in `CoreGraphics`
  - `enet_allocate_packet_payload_default` in `RESync`
  - dyld PAC dispatch table entries for `pacda`, `autia`, `pacia`, `autda`
  - `CFRunLoopObserverCreateWithHandler` as a stable PAC-signed anchor
- `SegmenterExploit.va()` clones and rewrites the rule table, corrupts iterator state, injects a fake vtable, rewires the delegate, and arranges a gadget chain so `iterator.next()` invokes an attacker-selected target.
- The call chain is:

```text
iterator.next()
  -> fake vtable entry
  -> _autohinter_iterator_end
  -> _autohinter_iterator_begin
  -> enet_allocate_packet_payload_default
  -> target function
```

- After the call returns, the code restores the original state.

Final Stage2 surface:

- `pacda`
- `pacia`
- `autda`
- `autia`
- PAC-signed indirect call helpers

Important anchors:

- layout constants: `Stage2_16.3_16.5.1_seedbell.js:734-760`
- gadget discovery: `:1219-1381`
- corruption and trigger: `:1404-1515`
- PAC wrapper build: `:647-723`

### 17.0-17.2.1 `seedbell`

The 17.x path keeps the same corruption target and trigger:

- still `Intl.Segmenter`
- still corrupts `BreakIterator`
- still triggers with `a.next().value`

The main differences:

- gadget discovery was moved into `Stage2_16.6_17.2.1_seedbell_pre.js`
- gadget set changed slightly, for example `_HTTPConnectionFinalize` replaces the older `_dlfcn_globallookup` role
- the main branch adds a WASM-backed higher-arity call trampoline

Important anchors:

- pre-stage gadget resolution: `Stage2_16.6_17.2.1_seedbell_pre.js:402-608`
- PAC/sign/auth wrappers: `Stage2_17.0_17.2.1_seedbell.js:25-208`
- `BreakIterator` corruption path: `:347-460`
- WASM-backed call trampoline: `:464-506`

## Stage3: Loader And Bridge

Stage3 Variant B is the live loader that matters.

Important mechanics:

- `fetchBin()` rewrites every request for `/entry2_type0x0f.dylib` to local `TweakLoader.dylib`.
- `buildContainer()` rebuilds a `0xF00DBEEF` container from `payloads/manifest.json`.
- `feedRawBuffer()` copies the reconstructed bytes into the shared buffer.
- `wA()` services native requests by reading a string from the shared buffer, rebuilding the requested hash container, and writing the bytes back.
- `executeSandboxEscape()` loads `payloads/bootstrap.dylib`, finds `_process` via `LC_SYMTAB`, patches a branch if `_process` moved from `0x68d8`, maps the resulting image, and invokes the bootstrap entry trampoline.

Container format used by Stage3:

```c
struct ContainerHeader {
    uint32_t magic;   // 0xF00DBEEF
    uint32_t count;
};

struct ContainerEntry {
    uint32_t f1;
    uint32_t f2;
    uint32_t data_offset;
    uint32_t size;
};
```

Important anchors:

- `fetchBin()`: `Stage3_VariantB.js:1151`
- `buildContainer()`: `Stage3_VariantB.js:1177`
- `feedRawBuffer()`: `Stage3_VariantB.js:1222`
- poll loop: `Stage3_VariantB.js:1265`
- bootstrap mapping and branch patch: `Stage3_VariantB.js:1299-1388`

## Native Bootstrap: `bootstrap.dylib`

For this section:

- callbacks, slot layouts, request formats, selector-record structure, record IDs, and call sequences are **Verified**
- labels such as "bootstrap", "anti-analysis gate", "downloader bridge", and "selector parser" are **Inferred** from role and data flow

### `_process` at `0x68d8`

`_process`:

- initializes runtime state
- sets up the callback registry
- runs environment checks
- runs selector/manifest setup
- allocates a copy of the state block
- spawns the detached background worker (`sub_6C44`)

### `sub_8210` at `0x8210`

`sub_8210` clears a 24-slot registry and installs six handler pointers. This is the record-store backend that later indexes records by `f1`.

### `sub_71FC` at `0x71fc`

This routine acts as an environment / anti-analysis gate. The checks below are **Verified**; the label is **Inferred** from their effect:

- `stat("/usr/libexec/corelliumd")`
- `sandbox_check(..., "iokit-get-properties", ...)`
- IOKit serial-number checks against `CORELLIUM`
- CPU capability / VM heuristics

It returns a single-byte environment verdict via the caller-supplied pointer.

### `sub_987C` at `0x987c`

This routine acts as the JS/native request bridge. The buffer protocol below is **Verified**; the downloader-bridge label is **Inferred** from the surrounding JS interaction:

- waits on a semaphore
- writes the primary request string at full-buffer offset `+0x4` (`bytes + 0x0` once the leading opcode dword is skipped)
- optionally writes a secondary string at full-buffer offset `+0x800000` (`bytes + 0x7ffffc`)
- flips the request opcode to `1` or `7`
- busy-waits until JS answers with opcode `3` or `4`
- on success, copies `size` from full-buffer offset `+0x4` and payload bytes from `+0x8` (`bytes + 0x0` / `bytes + 0x4`)

That matches `Stage3_VariantB.js:wA()` and `feedRawBuffer()` exactly.

### `sub_9CB8` at `0x9cb8` and `sub_9F18` at `0x9f18`

These routines parse the raw `0x12345678` selector record and choose the payload hash for the current environment. The structure walk and returned values are **Verified**; the selector-parser framing is **Inferred** from their role.

The selector key is built from:

- OS version
- platform model
- architecture class
- several environment flags

`sub_9F18` then walks 100-byte selector records and synthesizes the final URL/hash path.

Recovered selector blob layout:

```c
struct SelectorBlob {
    uint32_t magic;        // 0x12345678
    uint32_t field_04;     // observed value 3
    char base_path[256];   // starts at offset 0x8
    uint32_t count;        // offset 0x108
    struct SelectorRecord records[count]; // offset 0x10c
};

struct SelectorRecord {
    uint32_t selector_key;
    uint8_t prefix32[32];  // opaque per-payload sideband, sent separately as request 0x70002
    char filename[64];
};
```

Observed 17.0.3 sample:

- `base_path = "./"`
- record 0 prefix: `85ab5908ceb1981df3449b52155a5026561c51d6f9f599acc99c5203b14733eb`
- record 0 filename: `4612aa650e60e2974a9ec37bbf922c79635b493a.min.js`
- record 1 prefix: `b252669de4b4adc34114fdf10d75f66b3efad6280f4fcd19603f6fac5873ede2`
- record 1 filename: `4817ea8063eb4480e915f1a4479c62ec774f52ce.min.js`

Additional selector findings from the recovered 14 blobs:

- the 28 raw records collapse to only 10 unique `(selector_key, prefix32, filename)` triplets
- `sub_9F18` chooses by `selector_key`, returns `base_path + filename`, and also returns a pointer to `prefix32`
- `sub_A418` then sends:
  - request `0x70001`: selected `base_path + filename`
  - request `0x70002`: the raw 32-byte `prefix32`
- the older 17.0.3 loader in `exploit_page_binaner.html` sets the salt to `cecd08aa6ff548c2` and fetches remote modules as `sha256(salt + module_id).substring(0, 40) + ".js"`
- that older loader executes the fetched response directly with `new Function(...)`; there is no visible decrypt step and no post-fetch MAC/checksum comparison
- Stage3 stores the raw sideband field unchanged as `fixedValue2` / `cA` and concatenates it into the generated native payload buffer; it does not hash, decrypt, or verify it on the JS side
- the `prefix32` value is invariant for a given selected asset across payload-set variants, but it is not the SHA1 or SHA256 of the recovered `.min.js` bytes

That makes `prefix32` best described as opaque per-selected-payload sideband metadata for the native stages. The JS-side handling and invariance are **Verified**; ruling out selector, filename, digest, decrypt, or verifier semantics is **Inferred** from the recovered usage.

### `sub_8430` at `0x8430`

This is the LZMA decompressor:

- header magic `0x0BEDF00D`
- decoded with `_compression_decode_buffer`

### `sub_6C44` and `sub_5FEC`

The worker and setup path perform the handoff from bootstrap setup into the native chain. The concrete actions below are **Verified**; the "post-bootstrap setup" label is **Inferred**:

- background task registration through `UIApplication`
- optional SIGSEGV wrapper for some branches
- fetch record `0x70000`
- decide between direct inherited mappings and a helper mapping path
- fetch and activate record `0x80000`
- continue into the `0x80000` native dispatch dylib

## Record Contracts

The stable record IDs in the modern payload sets are:

- `0x70000`
- `0x70005`
- `0x50000`
- `0x80000`
- `0x90000`
- `0x90001`
- `0xA0000`
- `0xF0000`

The filename is secondary after Stage3 rebuilds the container. `f1` is the real contract.

Resolved role split. Record IDs and consumers are **Verified**; the role labels are **Inferred** from call sites and control flow:

- `0x50000` is a raw arm64 helper loader blob used only on the auxiliary bootstrap path.
- `0x90000` is the main driver object resolved by `0x80000`.
- `0x90001` is a transient helper-driver object used by bootstrap to control `0x50000`.
- `0xA0000` is the cleanup module invoked from the `sub_7410` worker-thread dispatch path before `_startr`.

Additionally, the `0x80000` image internally references at least three record IDs that do not appear in the Stage3 manifest:

- `0x10000`: loaded image from which `_startx` is resolved (in the `sub_6BA0` / `_startr` continuation path).
- `0x30000`: loaded image from which `_starti` is resolved (in the `sub_BA2C` multi-path activation).
- `0x40000`: data blob passed as input to `_starti`.

These records are not present in `payloads/manifest.json` and are not fetched from the JS side via `buildContainer()`. Their backing records are configuration-dependent and may be absent in some runs, but the exact non-fatal handling is path-specific rather than universal: `_startx` lookup from `0x10000` is skipped when the resolver returns an error, while `sub_BA2C` returns `708614` when `0x30000` is absent and callers decide whether that is fatal. Their runtime origin remains untraced.

## `0x50000` And `0x90001`: Auxiliary Bootstrap Helper Path

This pair is only used in the fallback/helper mapping branch inside `bootstrap.dylib:sub_5FEC`. The branch membership is **Verified**; calling it the auxiliary helper path is **Inferred** from its role.

### `0x90001`

`0x90001` (`entry5_type0x09.dylib`) exports `_driver` just like `0x90000`, but bootstrap uses it differently. The export surface and bootstrap call pattern are **Verified**; its distinction as a separate control-plane object is **Inferred**.

Recovered interface object from `_driver`:

- `+0x10` `sub_7714`: free the outer object
- `+0x18` `sub_7794`: create/init session object via `sub_3F5E4`
- `+0x20` `sub_78B8`: destroy/cleanup session object via `sub_3FBE4`
- `+0x28` `sub_7808`: command dispatcher via `sub_3F758`
- `+0x30` `sub_7868`: secondary state operation
- `+0x38` `sub_7908`: read cached status at `session + 6424`
- `+0x40` `sub_7994`: batch dispatcher
- `+0x48` `sub_7AFC`: kernel version triple

Bootstrap wrapper mapping:

- `sub_8590` loads record `0x90001`, resolves `_driver`, instantiates the object, PAC-fixes the vtable entries with `sub_5D2C`, and stores a 16-byte wrapper:
  - `[0x0]` loaded image handle
  - `[0x8]` helper object pointer
- `sub_87D8` calls wrapper method `+0x18`
- `sub_8840` calls wrapper method `+0x28`
- `sub_88B4` calls wrapper method `+0x20`
- `sub_8928` calls wrapper method `+0x10`, unloads the image, and frees the wrapper

Observed bootstrap command sequence:

1. `sub_8590(a1, 0x90001, &helper)`
2. `sub_87D8(helper, 0, &session)`
3. `sub_8840(helper, session, 0xC000001B, &state)` as a readback/query pass over the stage-1B state bytes
4. fallback `sub_8840(helper, session, 0x4000001B, &state)` as the state-setting path if the query pass does not populate the expected bytes
5. `sub_8840(helper, session, 13, 0)`
6. bootstrap maps the 16 MB helper region and copies `0x50000` into it
7. `sub_8840(helper, session, 38, 0)`
8. `sub_88B4(helper, session)`
9. `sub_8928(a1, helper)`

Recovered command dispatch in `sub_3F758`:

- `13` -> `sub_3C034(a1, mach_task_self_, 0)`
- `22` -> same path with caller-supplied or self task port
- `38` -> `sub_3BEC4(a1, mach_task_self_)`
- `0x40000010` -> `sub_2E0B0(a1)`
- `0x4000001B` -> `sub_3C354(a1)` after version/feature gating; this is the state-setting path
- `0xC000001B` -> `sub_3CA24(...)` after the same gating; this is the readback/query path and returns three booleans from task-linked flags

So `0x90001` is not the main exploit service object used by the later `0x80000` / `0x90000` path. Its description as a bootstrap-time control plane for helper mapping is **Inferred** from the observed command set and call context.

### `0x50000`

`0x50000` (`entry4_type0x05.bin`) is raw arm64 position-independent code. It is not a plain data blob, and it is not a stripped Mach-O. Those format properties are **Verified**.

Recovered structure:

- offset `0x0`: tiny init stub that writes three internal function pointers into a caller-supplied struct
  - `0x1024`
  - `0x3334`
  - `0x340c`
- offsets `0x24..0x1a8`: direct syscall veneers using `svc #0x80` with errno normalization
- offsets `0x1ac..0x1023`: large reserved zero-filled block
- offset `0x1024`: large loader routine

Important behavior from the loader routine:

- walks backward by page until it finds `MH_MAGIC_64` (`0xFEEDFACF`)
- accepts FAT magic `0xCAFEBABE` / `0xBEBAFECA`
- iterates FAT slices and Mach-O load commands
- uses helper routines at `0x3334` and `0x340c` that behave like symbol-resolution / callback-execution support for the loaded image

Observed bootstrap contract from the live call sites:

- bootstrap copies `0x50000` to `rx_base + vm_page_size` and immediately calls that copied entry stub through the PAC trampoline
- the entry stub writes three helper callbacks into the bootstrap context:
  - `ctx + 0x30 = 0x1024`: load external image bytes
  - `ctx + 0x38 = 0x3334`: resolve a symbol from a loaded image
  - `ctx + 0x130 = 0x340c`: unload/finalize a loaded image
- bootstrap's wrapper table then uses those callbacks as:
  - `ctx + 0xF8 = sub_7ED4`: load a record's bytes through `ctx + 0x30`
  - `ctx + 0x100 = sub_7FC8`: unload a record through `ctx + 0x130`
  - `ctx + 0x108 = sub_8080`: return the loaded-image handle, loading first if needed

Observed live-use sequence in `bootstrap.dylib:sub_5FEC`:

- `ctx + 0xF8` is called with record id `0x80000`, which routes the `0x80000` record bytes and length into the `0x50000` loader
- `ctx + 0x108` is then called with record id `0x80000` to recover the loaded-image handle
- `ctx + 0x38` is called with that handle and the string `"_start"` to resolve the `0x80000` entrypoint
- bootstrap calls the resolved `_start` directly with `x0 = ctx`
- `ctx + 0x100` is then called with record id `0x80000` to unload / clear the temporary loaded-image handle

The embedded string table includes:

- `__PAGEZERO`
- `__TEXT`
- `__DATA`
- `__LINKEDIT`
- `/usr/lib/libobjc.A.dylib`
- `/usr/lib/system/libsystem_pthread.dylib`
- `/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore`
- `JSEvaluateScript`

That makes `0x50000` best described as a flat manual-loader/runtime module with syscall veneers and embedded loader metadata. The loader behavior and live-use sequence are **Verified**; the "manual-loader/runtime module" label is **Inferred** from those mechanics.

### IPSW / Firmware Correlation For The Helper Path

The 17.0.3 IPSW-derived dyld and XNU artifacts tighten the exact role of this branch:

- `bootstrap.dylib:sub_5FEC` calls `task_info(mach_task_self_, TASK_DYLD_INFO, ...)` and reads `all_image_info_addr`
- it then reaches `dyld_all_image_infos + 0x28`, which is `jitInfo` in the public `dyld_all_image_infos` layout
- after the helper branch allocates the executable helper region and companion 16 MB data region, it stores the control pointer through that `jitInfo` slot

Primary-source backing:

- in 17.0.3 dyld, `dyld4::ExternallyViewableState::switchToDyldInDyldCache()` registers `_dyld_all_image_infos` via `proc_set_dyld_all_image_info(&dyld_all_image_infos, 368)`
- in XNU, `TASK_DYLD_INFO` returns only `all_image_info_addr`, `all_image_info_size`, and format from `task->all_image_info_*`
- XNU exec paths copy in the dyld anchor structure as metadata, but there is no 17.0.3 dyld or XNU path that operationally consumes `jitInfo`

That changes the precise interpretation. The dyld/XNU facts and the bootstrap writes are **Verified**; the usage conclusions below are **Inferred** from those facts:

- `0x50000` is not “run by dyld through jitInfo”
- the helper branch maps and arms the raw `0x50000` helper region itself
- `jitInfo` is used as a stable, debugger-visible rendezvous / publication slot for the helper control page

The helper-driver commands line up with that interpretation:

- command `13` toggles the version-specific `vm_map` bit matching `jit_entry_exists` (`0x400`)
- command `38` adjusts `pmap->min` / `pmap->max` bounds against the saved helper-side `pmap`

So the firmware-backed description is:

- `0x90001` prepares task / `vm_map` / `pmap` state for the auxiliary helper mapping path
- bootstrap copies `0x50000` into an executable helper region and publishes that region through `dyld_all_image_infos.jitInfo`
- bootstrap itself then uses the installed `0x50000` callbacks to load record `0x80000`, resolve `_start`, call it, and unload the temporary handle
- none of that loading or dispatch is performed by dyld; `jitInfo` remains only a rendezvous / publication slot

## `0x80000`: Orchestrator Dylib

Two size variants are observed across the payload sets: 228928 bytes (the 377bed variant documented in the original writeup) and 196864 bytes (the e9f89858 variant analyzed below). Both share the same export surface.

For this section:

- control flow, exported symbols, record IDs, callbacks, and offsets are **Verified**
- labels such as "orchestrator", "post-exploit dispatch", and "continuation" are **Inferred** from role and call graph

### Exports (377bed variant)

- `_start` at `0x8754`
- `_startl` at `0x8228`
- `_startr` at `0x8d90`
- `_startm` at `0x94dc`

### Exports (e9f89858 variant)

- `_start` at `0x65fc`
- `_startl` at `0x60f4`
- `_startr` at `0x6ab0`
- `_startm` at `0x71ec`

The orchestrator also carries these symbol strings, indicating it resolves them from other records at runtime: `_startsc`, `_startx`, `_starti`.

### `_start`

`_start` patches four callback slots in the copied bootstrap context (`ctx + 40`, `ctx + 176`, `ctx + 288`, `ctx + 296`), then:

1. resolves `_driver` from record `0x90000`
2. calls `_driver` to obtain a vtable-backed interface object
3. validates the object header: word `0x0002` and version `>= 2`
4. resolves `_startl` from record `0x80000` and calls `_startl(ctx, driver_obj)`

So `_start` is the handoff from the bootstrap record store into the native driver/service object.

### `_startr`

`_startr` pulls record `0x70005` (`458757`) from the record store, expects:

- minimum size `0x18`
- magic `0xDEADD00F`

and then uses byte offset `0x4` (not `0x5` — byte `0x5` is the second byte of the flags dword but this variant reads the whole byte at `+0x4`) as the boolean mode flag, with the TTL dword coming from offset `0x8`, before continuing into `sub_6BA0` (e9f89858 variant) / `sub_8E84` (377bed variant).

In the e9f89858 variant, `_startr` at `0x6ab0` calls `sub_6BA0(ctx, mode_flag, 1)`.

Observed fields in the live `0x70005` blob after the magic. The blob we recovered is larger than the `0x18` minimum accepted by `_startr`:

- raw flags dword at offset `0x4` with the mode byte read from byte `0x4` in the e9f89858 path
- TTL `0x15180` (`86400`) at offset `0x8`
- `0x7d0` at offset `0xc`
- `1` at offsets `0x10` and `0x14`
- `2` at offset `0x18`
- string descriptor `offset=0x24`, `length=0xc`
- trailing string: `SpringBoard`

### `sub_21188`

This is the validator/loader for record `0xF0000`:

- fetches record `983040`
- requires size at least `0x21`
- accepts FAT or thin Mach-O magic:
  - `0xBEBAFECA`
  - `0xCAFEBABE`
  - `0xCEFAEDFE`
  - `0xCFFAEDFE`

### `sub_20024`

This is the symbol resolution contract for the `0xF0000` image:

- resolve `_last`
- if missing, resolve `_end`

If neither symbol exists, loading fails.

### `sub_1FE70`

This helper fetches `0xF0000`, obtains a task/mapping context, and packages the loaded image together with the task port and mode flags for later symbol resolution.

### `_startl` Internals (e9f89858 variant at `0x60f4`)

`_startl` receives `(ctx, driver_obj)` from `_start` and:

1. Creates a record store session via `sub_1C954`.
2. Gets the kernel version triple via the driver object's `+0x20` method.
3. Registers up to three string records from the bootstrap context:
   - `ctx + 120` → `0x70003`
   - `ctx + 160` → `0x70004`
   - `ctx + 168` → `0x70006`
4. Creates a 0x38-byte thread pack containing the driver object, kernel info buffer, string record handles, and a mode byte.
5. Spawns `sub_71F8` on a new pthread (detached unless `ctx + 1478` forces join).

The thread pack layout:

- `+0x00` driver object
- `+0x08` mode byte (inverted from `ctx + 1478`)
- `+0x10` kernel version buffer
- `+0x18` kernel version buffer size
- `+0x20` `0x70004` string handle
- `+0x28` `0x70006` string handle
- `+0x30` `0x70003` string handle

### Worker Thread `sub_71F8` → `sub_7410`: Main Post-Exploit Dispatch

`sub_71F8` is the thread entry. It calls `sub_A238` to build a runtime context (creating a record store, registering `0x70003` and `0x70004` strings, calling `sub_C320` for the record-store builder), then calls `sub_7410` for the main dispatch.

`sub_7410` is the core worker-thread dispatch function. The step order below is **Verified**; calling it the main post-exploit dispatcher is **Inferred** from its role in the call graph.

1. **Entitlement injection:** injects a baked plist fragment granting:
   - `com.apple.private.webbookmarks.settings`
   - `com.apple.private.security.storage.DiagnosticReports.read-write`
2. **Exception guard suppression:** calls `task_get_exc_guard_behavior` / `task_set_exc_guard_behavior` to clear bits `0x88` from the guard mask, preventing crash reports during exploit activity. The original mask is restored at the end.
3. **Environment check:** calls `sub_7B18` to probe runtime conditions.
4. **Cleanup-module dispatch:** resolves `_startsc` from record `0xA0000` (655360) via `sub_7BA0(ctx, 655360, "_startsc", ...)` and calls it. If the record is missing (error 28675), execution continues without cleanup.
5. **Unloads `0xA0000`** via `ctx + 224` callback with flush mode `4`.
6. **Atomic one-shot gate:** uses `ldaxr`/`stlxr` to ensure the following dispatch runs exactly once per process.
7. **Resolves and maps `0x80000`** via `ctx + 104` callback, then builds a dispatch table via `sub_7CA4`.
8. **`_startr` dispatch:** iterates the dispatch table entries. For type `1` with size `4`, dispatches `_startr` via `ctx + 240` callback. For types `2`–`3`, dispatches via `ctx + 248`.
9. **Post-startr cleanup:** deletes crash reports from:
   - `/private/var/mobile/Library/Logs/CrashReporte_/`
   - `/var/containers/Shared/SystemGroup/systemgroup.com.apple.osanalytics/DiagnosticReports`
   using `sub_7D58` with time-based filtering.
10. **String record dispatch:** executes `0x70001` and `0x70003` string payloads via `sub_7DC4(sub_7EA4, string_ptr)` on background threads.

### `sub_6BA0`: `_startr` Continuation (e9f89858 variant)

Called from `_startr` with `(ctx, mode_flag, 1)`. This call relationship is **Verified**; describing it as a second-stage orchestrator is **Inferred** from the subsequent record and thread dispatch work.

Key recovered behavior:

1. If `mode_flag & 1` or the third arg is set, invokes the driver object's method at `+0x40` (batch dispatcher) when `dyldVersionNumber >= 1066.0`.
2. Fetches records `0x70004` (458756) and `0x70006` (458758) from the record store.
3. On the non-mode path: fetches `0x70001` (selected path), `0x70004`, and `0x70002` (prefix32 sideband). Calls `sub_863C` with the selected path, `sub_833C` with the prefix32 data, and `sub_8200` to compose an output buffer that is written back to the record store via the `+0x10` method. This is how the `prefix32` sideband is propagated into the native record store.
4. Builds a runtime context via `sub_A0A4` from the record store, driver, and string records.
5. Resolves `_startx` from record `0x10000` via `sub_7BA0(ctx, 0x10000, "_startx", ...)`. If found, calls it via `sub_7DC4(sub_8014, ctx)` (threaded execution).
6. Calls `sub_8DD0` to clean up string data after completion.

So `sub_6BA0` is where the `prefix32` sideband is ultimately consumed on the native side: it is composed with the selected-path string and written as a combined buffer into the record store for downstream consumption.

## `0xA0000`: Anti-Forensics Cleanup Module

Present as `entry4_type0x0a.dylib` in payload sets that include it (e9f89858, f4120dc6, c8a14d79, 1b2cbbde). Record ID `0xA0000` (655360). 36 functions, relatively small binary.

For this section:

- exported symbols, file paths, deletion routines, and control parameters are **Verified**
- the "anti-forensics" label and "exploit traces" framing are **Inferred** from the targeted paths and surrounding call context

### Export

- `_startsc` at `0x78f0`

### Entry Contract

`_startsc(ctx, session_handle, control_block)`:

- `ctx` header word must be `4` and version `>= 6`.
- Reads a record-count threshold from `ctx + 160`, requires `count >> 3 >= 0x44B`.
- Calls `ctx + 128` to set up the session.
- `control_block` (optional):
  - byte `+0x0`: enable flag. If `0`, cleanup runs. If nonzero, cleanup is skipped.
  - dword `+0x4`: age threshold in seconds for time-filtered file deletion.
- If `session_handle` is zero on entry, calls `ctx + 136` and `ctx + 144` to release the session on exit.

### Cleanup Targets

When enabled, `_startsc` calls `setsid()` to detach from the controlling terminal, then systematically deletes:

**Recursive directory deletion (via `sub_6F70`):**
- `/private/var/mobile/Library/Caches/com.apple.suggestd/WebKit` (with age filter)
- `/private/var/db/diagnostics/Persist` (all files, no age filter)
- `/private/var/db/diagnostics/Signpost` (all files, no age filter)
- `/private/var/db/diagnostics/Special` (all files, no age filter)
- `/private/var/db/analyticsd/aggregates/Daily` (all files, no age filter)
- `/private/var/db/analyticsd/aggregates/90Day` (all files, no age filter)
- `/private/var/db/analyticsd/aggregates/Never` (all files, no age filter)

**Targeted file deletion by name prefix (via `sub_72A8`):**
- `/private/var/log/com.apple.xpc.launchd/launchd.log`
- `/private/var/db/diagnostics/logdata.statistics`
- `/private/var/mobile/Library/Logs/AppleSupport/general`
- `/private/var/mobile/Library/Logs/CrashReporte_/com.apple.WebKit.WebContent*`
- `/private/var/mobile/Library/Logs/CrashReporte_/ExcUserFault_com.apple.WebKit.WebContent*`
- `/private/var/mobile/Library/Logs/CrashReporte_/JetsamEvent*`
- `/private/var/mobile/Library/Logs/CrashReporte_/com.apple.WebKit.GPU-*`

**Flat directory age-filtered scan (via `sub_7658`):**
- `/private/var/mobile/Library/Logs/CrashReporte_/`

### Helper Functions

- `sub_6F70(path, remove_root, age_threshold)`: recursive directory tree deletion. If `age_threshold != 0`, only deletes files whose `ctime` is within `age_threshold` seconds of `time()`. If `remove_root`, also `rmdir`s the directory itself.
- `sub_72A8(dir, prefix, suffix, age_threshold)`: opens `dir`, iterates entries, deletes regular files whose name starts with `prefix` and optionally ends with `suffix`, subject to the same age filter. Recurses into subdirectories.
- `sub_7658(dir, age_threshold)`: flat directory scan, deletes regular files within the age threshold.
- `sub_7238(path)`: single file `unlink` with `chmod 0755` before deletion.

### Purpose

This module deletes WebKit-related crash reports, JetsamEvent logs, diagnostic logs, and analytics aggregates from the `sub_7410` worker-thread dispatch path before `_startr` runs. The path targets and call order are **Verified**; interpreting this as anti-forensics cleanup of exploit traces is **Inferred** from those targets and the surrounding execution context. The entitlements injected by `sub_7410` (`com.apple.private.security.storage.DiagnosticReports.read-write`) are likely prerequisites for accessing several of these paths.

### `sub_BA2C`: `_starti` Dispatcher

`sub_BA2C` is called from 7 locations within the 0x80000 image. The call count and behavior below are **Verified**; the `_starti` dispatcher label is **Inferred** from the resolved symbol and invocation pattern:

1. Fetches record `0x30000` (196608) and loads it as a Mach-O image.
2. Fetches record `0x40000` (262144) as raw data.
3. Fetches record `0x90000` (589824) as raw data.
4. Resolves `_starti` from the loaded `0x30000` image.
5. Calls `_starti(out_ctx, data_40000, size_40000, data_90000, size_90000, field_24, field_32)`.
6. `_starti` returns a context object with header word `4` — the same context type consumed by `_startsc`.

The records `0x30000` and `0x40000` are not present in `manifest.json` and their origin at runtime is not yet traced.

## `0x90000`: Driver-Facade Dylib

### 377bed variant

Export:

- `_driver` at `0x5ec4`

`_driver` allocates a `0x50`-byte vtable-backed object (header word `0x20002` = version 2.2) and installs these methods:

- `sub_5F9C`: destructor/free
- `sub_5FDC`: create/init state object via `sub_3E42C`
- `sub_608C`: validation / refresh path
- `sub_6030`: main dispatcher wrapper around `sub_3E580`
- `sub_6070`: teardown/release helper
- `sub_60A8`: read a cached status field at offset `+6424`
- `sub_60EC`: batch dispatcher over a list of operations
- `sub_6224`: query kernel version triple

### e9f89858 variant

Export:

- `_driver` at `0x600c`

Same 0x50-byte object with header `0x20002`. Vtable methods:

- `+0x10` `sub_60B0`: destructor/free (zeroes all five 128-bit blocks, then `free`)
- `+0x18` `sub_60E8`: create/init state object via `sub_331EC`
- `+0x20` `sub_6138`: main dispatcher
- `+0x28` `sub_6190`: teardown via `sub_340FC`
- `+0x30` `sub_6174`: teardown/release helper
- `+0x38` `sub_61AC`: cached status reader
- `+0x40` `sub_61F0`: batch dispatcher
- `+0x48` `sub_6324`: kernel version triple — parses `xnu-MAJOR.MINOR.PATCH` from `host_kernel_version()`, requires `RELEASE` kernel

The kernel version method (`sub_6324`) explicitly rejects non-RELEASE kernels and falls back to `sysctl CTL_KERN.KERN_VERSION` if `host_kernel_version()` returns error `53`.

### State Initialization

Both variants allocate a `0x1D60`-byte state object. The 377bed variant uses `sub_3E42C` → `sub_3CCA8`; the e9f89858 variant uses `sub_331EC` → `sub_31BA0`. The init function is the actual exploit setup — it is the largest single function in the binary.

Evidence labels used in this section:

- **Verified**: directly observed in decompilation / disassembly / constants.
- **Inferred**: conclusion drawn from control flow, data flow, or repeated usage, but not named explicitly by the binary.
- **Hypothesis**: plausible label or external identification that is not proved by the binary alone.

Recovered sequence from the e9f89858 variant (`sub_31BA0`, ~500 lines of pseudocode):

#### 1. Environment gating

- `mach_timebase_info`, `pthread_mutex_init` x2, `semaphore_create`
- Kernel version triple stored at `state + 320` (XNU major). Observed values:
  - `6153` = xnu-6153 (iOS 13.x/Darwin 19)
  - `7195` = xnu-7195 (iOS 14.x/Darwin 20)
  - `8019`/`8020` = xnu-8019/8020 (iOS 15.x/Darwin 21)
  - `8792`/`8796` = xnu-8792/8796 (iOS 16.x/Darwin 22)
  - `10002` = xnu-10002 (iOS 17.x/Darwin 23)
- Kernel address/slide stored at `state + 344` as a 64-bit value. The init path applies multiple threshold checks rather than a single simple range: an early coarse gate rejects values outside a broad startup window, and later logic enforces `0x1C1B1914600000` through `0x225C1E804FFFFF`, with values above `0x1F543C41E00000` rejected on builds < 8792.

#### 2. Anti-analysis checks

- `stat("/usr/libexec/corelliumd")` → reject if exists
- `sandbox_check(getpid(), "iokit-get-properties", SANDBOX_CHECK_NO_REPORT)` → reject if sandboxed
- IOKit serial number check: reads `IOPlatformSerialNumber` from `IODeviceTree:/`, rejects `CORELLIUM` prefix
- CPU capability probe: specific CPU families get additional gating. The numeric constants are **Verified**; SoC-family naming such as `hw.cpufamily == 458787763` = A15 Blizzard/Avalanche is **Hypothesis** from external mapping.

#### 3. CPU family → capability flags

The exploit branches on `hw.cpufamily`. Capability bits are **Verified**; the SoC-family names in the table are **Hypothesis** from external mapping:

| CPU family constant | SoC family | Capability flag set |
|---|---|---|
| `-2023363094` | A16 Everest/Sawtooth | `0x1000000` + `32` |
| `458787763` | A15 Blizzard/Avalanche | `0x80000`, plus `8` on newer builds |
| `678884788` | A17 Pro | `0x4000000` + `32` |
| `-1829029944` | A14 Lightning/Thunder | `0x2000` |
| `-634136515` | M1/M2 family | `0x100000`, plus `32` or `8` depending on core count and build |
| `1463508716` | newer variant | `0x80000` with kernel-address gating |
| `131287967` | older variant | `1` |

On newer kernels (`state + 344 > 0x1F530F027FFFFF`), also reads `hw.model` via sysctl and checks `model[0] & 0xDF == 0x4A` (uppercase 'J' → iPhone model prefix).

#### 4. State inheritance — fast path before the exploit

Before running the full exploit, `sub_31BA0` first attempts to **inherit** a previously-published kernel primitive from shared memory. Three version-dependent recovery functions are tried:

**`sub_9DC8` (newest, `state+344 > 0x2257FFFFFFFFFFFF`):**
- Calls `sub_137E4(state, 17, 0x4000, &ptr)` which resolves a handle keyed at `0x1122334455667788 + 17` (or reads from a mailbox slot table on newer builds), obtains a memory entry port, and `vm_map`s 4 pages of shared memory. The keying and mapping are **Verified**; calling it a `host_create_mach_voucher` recipe is **Inferred**.
- Scans the mapped region for a dword value `8` at page-aligned boundaries — this is a magic marker left by a prior run.
- When found, copies 0x6D0 bytes of pre-built exploit state from the template, clears stale fields, and finishes IOSurface setup via the same `sub_A048` → `sub_A2D0` → `sub_A4A8` → `sub_A508` sequence used by the full exploit.
- Maps a second shared region via `sub_137E4(state, 18, ...)` for additional state.

**`sub_13C5C` (middle, `state+344 > 0x1F530F027FFFFF` with state bits):**
- Resolves 3 Mach ports via mailbox-style keys from `0x3122334455667788 + offset` (on older builds) or from a slot table (on newer builds). The keys and port recovery are **Verified**; the “voucher mailbox” label is **Inferred**.
- On older builds (`<= 8791`): validates via `IOConnectCallMethod(connection[1], 0x3E7, ...)` (selector 999) and accepts the expected failure code. On newer builds this check is skipped.
- Maps `connection[0]` and `object` into memory. Reads pre-computed kernel state from the mapped page:
  - `+0x00`: kernel object address → `state + 6608`
  - `+0x08`: kernel region → `state + 240`
  - `+0x10`: index (uint32), `+0x14`: value (uint32) — used to correlate IOSurface backing
- Stores the IOSurface connect port and mapped window at `state + 232/248/256`.

**`sub_1393C` (oldest, below middle threshold):**
- Resolves 3–4 keyed handles starting from `0x1122334455667788`. The constant sequence is **Verified**; the exact voucher primitive label is **Inferred**.
- Converts voucher ports to file descriptors via `fileport_makefd()`.
- The kernel addresses are **smuggled through `fstat` metadata**: `st_atimespec.tv_sec` contains the kernel object address, `st_atimespec.tv_nsec` encodes the kernel base/slide via bit manipulation (`>> 40` × page_size → `state + 6624`).
- Stores fds at `state + 6448/6452/6456/6464` and the kernel object at `state + 6608`.

If any of these inherit successfully (`result == 1` plus the expected state fields are populated), the full exploit is skipped. If all fail, execution falls through to the actual vulnerability trigger in `sub_8A48`.

The **terminal helper families** (documented earlier as `sub_1DBD8`, `sub_1DE68`, `sub_1E154`, `sub_C060`) appear to **publish** the kernel state that these functions later inherit. The shared keys, slot writes, and `fileport_makeport` use are **Verified**; the producer/consumer framing is **Inferred**.

#### 5. Kernel primitive acquisition — the actual exploit (`sub_8A48`)

When state inheritance fails, `sub_8A48` runs the real IOSurface-based kernel exploit. The exploit loop is:

1. **`sub_72EC`** — IOSurface setup and kernel address leak
2. **`sub_E418`** — kernel object location and corruption trigger
3. **`sub_B8F8`** — version-dependent struct offset table
4. IOSurface pointer walk and primitive finalization

The loop retries up to 5 times on failure (error 258054).

##### Initial kernel address leak (`sub_72EC`)

This function opens `IOSurfaceRoot` via `sub_1BE64("IOSurfaceRoot", 120)`, then `dlopen`s the IOSurface framework and resolves: `IOSurfaceCreate`, `IOSurfaceGetBaseAddress`, `IOSurfaceGetAllocSize`, `kIOSurfaceAllocSize`, `kIOSurfaceMemoryRegion`, `kIOSurfaceCacheMode`, `kIOSurfaceIsGlobal`, `kIOSurfaceWidth`, `kIOSurfaceHeight`.

It creates an IOSurface via `sub_8754`, then **scans kernel memory through the IOSurface backing region** via `sub_719C(ctx, address, size, &output)`. The scan walks page-by-page searching for tagged kernel pointer patterns:

- **Pattern 1**: `!(ptr >> 27) && ptr > threshold && (ptr & 7) == 1` — a tagged kernel object pointer (threshold is `0x30000` for builds <= 8791, `0x800000` for newer)
- **Pattern 2**: `ptr >= 0xFFFFFFFF40000000 && ptr < 0xFFFFFFFF48000000 && (ptr & 7) == 0` — a PPL/KTRR-range kernel virtual address
- On builds >= 8792, a third value at `address + 16` is checked against the same PPL range

The scan starts from the IOSurface base plus `0x10000000` and walks upward. When matching patterns are found, the function reads `hw.model` via sysctl and proceeds with the Mach port spray.

The **initial address correlation** appears to come from the IOSurface `kIOSurfaceMemoryRegion` property — by controlling the memory region the surface is allocated from, the exploit influences the kernel address of the backing store. The property resolution and subsequent scanning are **Verified**; the exact causal interpretation is **Inferred**.

##### Kernel address leak via IOGPU/IOSurface selectors (`sub_DDBC`)

`sub_DDBC` derives kernel virtual addresses through two SoC-dependent paths:

**IOGPU path** (capability `0x8000`):
- Reads kernel address components from IOGPU external method selectors at `0x20AE00008` through `0x20AE00030` (6–8 sequential 32-bit reads).
- Combines pairs of 32-bit values into 64-bit kernel virtual addresses.
- Computes a base address for the scan range from the GPU firmware region metadata.

**IOSurface path** (capability `89670209`):
- Reads IOSurface external method selectors `0x200000680`/`0x200000684` (or `0x2000007E4`/`0x2000007E8` depending on CPU family).
- The result is a page index; multiplied by `page_size` and added to the IOSurface base → kernel address.
- These selectors expose page table or allocation metadata from the IOSurface userclient.

After deriving the base address, `sub_DDBC` calls `sub_E22C` to scan the kernel heap.

##### Kernel heap scan for IOKit objects (`sub_E22C` → `sub_F07C`)

`sub_E22C` scans backward from the derived address at page-size stride, reading a 32-bit value at each page via the userclient callback. It looks for the marker `0xFEEBDAED` — an IOKit allocation/metadata signature present in IOSurface-related kernel heap objects.

When `0xFEEBDAED` is found, `sub_F07C` validates the surrounding structure:
- Checks a count field in range 9–63
- Checks a type field == 2
- Checks a size field <= 2 × page_size
- Iterates embedded descriptors looking for type `5` entries
- Reads 272 bytes from the type-5 entry and validates that an embedded pointer at offset ~256 falls within the known kernel text range (`ctx+40` to `ctx+48`)

If validation passes, the address is stored at `ctx + 56` and used as the anchor for subsequent parsing.

##### Kernel object parse and offset computation (`sub_E418` → `sub_E2FC`)

`sub_E418` takes two callbacks (`sub_667C` for read, `sub_7024` for write) and:

1. Calls `sub_DDBC` to derive the kernel address and locate the IOKit heap object.
2. Reads via the callback from a version-dependent address; expects magic `0x484F6666`.
3. Allocates 0x4000 bytes and reads 4 pages of kernel memory.
4. Calls `sub_E2FC` to parse the read data. `sub_E2FC` searches for the marker `0x686F6D6D` in the buffer, extracts an entry count, iterates entries at stride 8 (or 6 on xnu-8796+), and looks for an entry with value `24`. From the matching entry it extracts two pointer-sized values and computes the final IOSurface kernel object address.
5. Computes a version-specific scan offset (ranging from `0x4000000` to `0x7B00000`) based on kernel address thresholds and CPU capability bits.
6. Calls `sub_F1F8` to verify the corruption target.

##### IOSurface object verification (`sub_F1F8`)

`sub_F1F8` is a **verification scanner**, not the corruption itself. It scans at IOSurface kernel object allocation strides, which are version-dependent:

| XNU build | Stride (bytes) |
|---|---|
| 7195 | 280 |
| 8019 | 296 |
| 8020 | 160 |
| 8792/8796 | 192 |
| 10002 | 208 |

At each candidate offset within a page, it reads 32 bytes and calls `sub_F410` to compare the first 16 bytes against an expected IOSurface header pattern (`xmmword_37440` / `xmmword_37430`), then validates the next two qwords as valid kernel pointers. When a match is found, the address is stored at `ctx + 136` as the confirmed IOSurface kernel object.

##### Version-dependent struct offsets (`sub_B8F8`)

After `sub_E418` succeeds, `sub_B8F8` computes the IOSurface kernel object field layout. Key offset tables map XNU build → struct field positions for the IOSurface backing pointer, pmap pointer, and page table entry locations. These offsets change substantially across xnu-7195 through xnu-10002.

##### Three exploitation tiers

`sub_8A48` then implements three separate primitive construction techniques selected by kernel address range:

**Path A — Newest kernels (`state+344 >= 0x1F530F02800000` with specific state bits, or `>= 0x2258000000000000`):**

This path uses IOSurface to build a direct kernel memory mapping:

1. Stores the exploit helper context at `state + 7488` and installs `sub_BD90` as the kread callback at `state + 48`.
2. Opens `IOSurfaceRoot` via `IOServiceMatching` → `IOServiceGetMatchingService` → `IOServiceOpen`.
3. Creates an IOSurface via `sub_C104(ctx, connect, &index)`.
4. Walks kernel object pointers from the IOSurface backing store:
   - Reads version-dependent offsets (280/256 or 288/264 depending on build > 8791)
   - Follows a chain: `surface_kaddr + offset_1` → `ptr_table + 8*index` → `+64` → `kobj`
   - Validates alignment: `page_size - (page_mask & kobj) >= 0x500`
5. Creates a `mach_make_memory_entry(mach_task_self_, &page_size, 0, VM_PROT_ALL|MAP_MEM_NAMED_CREATE, ...)` + `vm_map` pair — this gives userspace a page-aligned mapping.
6. Finds the kernel pmap-related structure by walking: `kobj → +32 → +56` on builds >= 7195 (deeper chain on newer kernels).
7. On builds >= `0x1F542301E00000`, applies an additional pointer transformation via `sub_1E99C`.
8. Resolves a kernel text region base via `sub_2B0A0` and constructs an IOSurface command descriptor:
   - `+32`: relative offset `(pmap_ptr - text_base) >> shift`
   - `+36`: `0x2000000` (operation flags)
   - `+0`: page count `(kobj & ~page_mask) / page_size`
   - IOSurface command code: `320`
9. Writes enable bits: `sub_1E8E0(state, pmap_ptr + 32)` (1-byte enable), `sub_1E0B8(state, pmap_ptr + 116, flags | 0x1000)`.
10. Maps the memory entry again — the mapped address becomes the direct kernel R/W window.
11. Stores: IOSurface connect at `state + 232`, kernel object address at `state + 240`, mapped address at `state + 248`, size at `state + 256`.

**Path B — Middle kernels (`state+344 >= 0x1C1B0A80100000` with state bits `0x5584001`, or `>= 0x1F530000000000`):**

Uses fd-pair + socket + IOSurface:

1. Creates fd pairs via `sub_1661C` (likely `pipe()`) and `sub_16724`.
2. Creates a UDP socket: `socket(AF_INET, SOCK_DGRAM, 0)`.
3. Opens `/private/etc/group` as a kernel fileref.
4. Walks kernel objects from the socket and pipe fds to correlate kernel addresses.
5. Scans for 7 consecutive valid kernel pointers aligned within the kernel text bounds — this is a vtable/dispatch table discovery technique for finding the kernel slide.
6. Stores four fd values at `state + 6448/6452/6464` and a kernel object pointer at `state + 536`.
7. Installs kread/kwrite primitives via `sub_179B0` on each fd.

**Path C — Oldest kernels (`state+344 < 0x1C1B0A80100000`):**

Fd-pair only approach:

1. Creates two fd pairs.
2. Searches for kernel pointer patterns using the fd pairs.
3. Stores four fds at `state + 6448/6452/6456/6460`.
4. Publishes kernel object at `state + 6608`.

All three paths retry up to 5 times on failure (error code 258054).

##### Vulnerability class

The exploit is best modeled as a **multi-stage IOSurface/IOGPU information disclosure → pmap permission escalation chain**, not a single classic memory corruption bug. The concrete reads, writes, and object walks below are **Verified**; the overall vulnerability-class label is **Inferred** from those mechanics:

1. **KASLR defeat**: IOGPU external method selectors (`0x20AE000xx`) and IOSurface selectors (`0x20000068x`/`0x2000007Ex`) expose kernel address components (page indices, virtual address fragments) from GPU firmware metadata and surface allocation internals.
2. **Kernel heap read**: The IOSurface userclient's memory-mapped backing region, combined with controlled `kIOSurfaceMemoryRegion` allocation, provides a window into kernel heap memory that the exploit uses to scan for IOKit object metadata (`0xFEEBDAED` markers, "math" structural signatures).
3. **IOSurface object identification**: The exploit locates a specific IOSurface kernel object by scanning at the version-dependent allocation stride (160–296 bytes) and matching the 32-byte header pattern. The "math" parse extracts the object's relationship to the pmap hierarchy.
4. **pmap permission modification**: The final writes target the IOSurface's pmap-related structure fields — `pmap_ptr + 32` (1-byte enable) and `pmap_ptr + 116` (set `0x1000` bit in permission flags). This modifies page table protections to grant the userspace process a direct read/write mapping into kernel memory via a subsequent `mach_make_memory_entry` + `vm_map`.
5. **No classic corruption**: There is no use-after-free, heap overflow, or type confusion. The primitive is built entirely from information disclosure through IOKit external methods, controlled memory mapping, and permission flag manipulation on existing kernel objects.

The vulnerability class is best described as a **PPL bypass via IOSurface/IOGPU info leak + pmap permission escalation**. That label is **Inferred** from the recovered mechanics rather than stated explicitly by the binary.

#### 6. Kernel read/write primitives

`sub_1E238` (kread) and `sub_1E0B8` (kwrite) select the appropriate backend based on which primitive was acquired:

| Priority | Condition | kread impl | kwrite impl |
|---|---|---|---|
| 1 | `state + 48` callback set | direct callback | `state + 64` callback |
| 2 | `state + 232` IOSurface connect valid | `sub_1D7F8` | `sub_1DBC0` |
| 3 | `state + 7488` newest helper set | `sub_ABD8` | `sub_AC54` |
| 4 | fd pairs + kptr (`6448/6452/6464/536`) | `sub_1C9B8` | `sub_1D334` |
| 5 | fd pairs only (`6448-6460`) | `sub_1C190` | `sub_1C2F0` |
| 6 | task port at `state + 6424` | `mach_vm_read` | `mach_vm_write` + `mach_vm_machine_attribute` |

The write fallback also flushes via `mach_vm_machine_attribute(task, addr, 4, MATTR_VAL_CACHE_FLUSH)`.

#### 7. Policy and entitlement patching

After the primitive is stable:

- Resolves `com.apple.security.sandbox` kext via `sub_1B5DC`
- Resolves `com.apple.driver.AppleMobileFileIntegrity` kext via `sub_1B5DC`
- For each kext: allocates a 0x128-byte helper, calls `sub_1305C` to initialize it
- Resolves `developer_mode_status` in AMFI `__DATA.__data` via `sub_15628`
- Resolves `allows_security_research` in AMFI `__DATA.__data` via `sub_15628`
- Reads current values via `sub_1DF78` (kread). If `developer_mode_status == 0`, writes `1` via `sub_1E8E0` (kwrite). Same for `allows_security_research`.

Baked entitlement plists for injection:

- `<dict><key>task_for_pid-allow</key><true/></dict>`
- `<dict><key>com.apple.private.iokit.IOServiceSetAuthorizationID</key><true/></dict>`
- `<dict><key>com.apple.private.vfs.snapshot</key><true/></dict>`
- `<dict><key>com.apple.private.security.disk-device-access</key><true/></dict>`
- `<dict><key>com.apple.private.diskimages.kext.user-client-access</key><true/><key>com.apple.private.security.disk-device-access</key><true/><key>com.apple.security.iokit-user-client-class</key><array><string>IOHDIXControllerUserClient</string></array></dict>`

#### 8. Task and host escalation

- Calls `sub_31350(state, mach_task_self_, 0, 0)` to re-apply task credentials
- Obtains `host_priv` port via `sub_2F660` → `state + 6432`
- Verifies host_priv is real by calling `host_get_special_port(host_priv, -1, 16, &port)` and expecting the returned port name to remain invalid / null. The check is **Verified**; identifying selector `16` as `HOST_KEXTD_PORT` is **Inferred** from external Mach naming.
- Calls `sub_306F4(state, mach_task_self_)` for task-level operations
- On older kernels: `sub_2F7A8` obtains an additional special port at `state + 6436`

#### 9. Terminal publication

Three paths depending on kernel version:

- `sub_14774` for `state+344 <= 0x1F530F027FFFFF` (oldest)
- `sub_14A04` for middle range with specific state bits
- `sub_9B74` for `state+344 > 0x2257FFFFFFFFFFFF` (newest, iOS 17)

### Command Dispatcher (`sub_33324` / e9f89858 variant)

The dispatcher exposes a rich selector-based API. Commands are grouped by `BYTE1(selector)`:

**Family 0 (`selector & 0xFF00 == 0`):** General task/kernel operations

| Selector | Description |
|---|---|
| `1` | Read task credential flags at version-dependent offsets. Checks `0x400` bit and `getppid()`. |
| `2` / `21` | `sub_2FC50` — task operation on self or specified port |
| `3` / `0x40000003` / `0x40000009` | `sub_11A88` — initialization |
| `6` | `sub_23950` — task setup on self |
| `7` | `sub_2F06C` + capture `mach_thread_self()` at `state + 6444` |
| `8` | `sub_2F1C8` — additional setup |
| `9` / `0x4000001A` | `sub_306F4` — task inspection |
| `10` | `sub_1A384` — mode set |
| `11` / `0x40000008` | `sub_2ED58` — entitlement injection |
| `12` | `sub_237B0` — task operation |
| `13` / `22` | `sub_2F954` — task port operation |
| `15` / `19` | `sub_2381C` — task flag set/clear |
| `20` | `sub_21A90` — write with data |
| `23` | `sub_32F9C` — task/host operation |
| `31` | `sub_318A0` + `sub_31350` — credential refresh |
| `34` | `sub_142A0` with `vm_protect` args |
| `38` | `sub_2F808` — pmap operation |
| `0x40000011` | `mach_vm_wire(host_priv, task, addr, size, prot)` — wire kernel memory |

**Family 1 (`selector & 0xFF00 == 0x100`):** Exploit primitive operations

| Selector | Description |
|---|---|
| `265` | `sub_10F94` — primitive build/test |
| `268` | Opens file by path (or `_CFProcessPath`), reads kernel object via `sub_250D8` |
| `269` | `sub_34644` — conditional on kernel address threshold (`state+344 >> 43 >= 0x44B`) |
| `0x4000010A` | `sub_18A4C` — targeted kernel operation |
| `0x40000105` | `sub_18B08` — data write to kernel |
| `-0x80000104` | `sub_11650` — status query |
| `-0x80000103` | `sub_10944` + `sub_345BC` — state probe |

**Family 3 (`selector & 0xFF00 == 0x300`):** Higher-level operations (older kernels only, `state+344 <= 0x1F52FFFFFFFFFFFF` and build <= 8791)

| Selector | Description |
|---|---|
| `0x40000301` | `sub_16EFC` — with single arg |
| `0x40000304` | `sub_16B20` — with offset arg |
| `0x40000305` | `sub_16A08` — complex multi-arg |
| `0x40000306` | `sub_174FC` — data operation |
| `0x302` (770) | `sub_16D70` — standalone |
| `-0x80000302` | `sub_17448` — read with output |
| `-0x3FFFFF03` | `sub_16B68` — read with data output |

**Selector `0xC000001B` (query):** Returns available capability bitmask. Caller supplies requested bits; dispatcher returns only the subset available. Supported bits: `0x1`, `0x2`, `0x4`, `0x8`.

**Selector `0x4000001B` (task flag set):** Already documented above in the selector contract section.

### Concrete Selector Contract

The main dispatcher is not just a monolithic “do exploit things” entrypoint. The modern 17.x path exposes concrete selector contracts that `0x80000` actually uses.

Observed selectors in the recovered 17.x driver:

- `0xC000001B`
  - query/readback path
  - the caller supplies a 32-bit requested bitmask in place
  - the dispatcher writes back only the subset it considers available on the current kernel/build
  - the supported bits are `0x1`, `0x2`, `0x4`, and `0x8`
- `0x4000001B`
  - task flag setter path
  - payload layout is:

```c
struct Driver1BRequest {
    uint32_t task_port;   // 0 => mach_task_self_
    uint8_t flag_04;
    uint8_t flag_05;
    uint8_t flag_06;
    uint8_t reserved_07;
};
```

The modern `sub_3AE94` path stores those three flag bytes into a task-local 32-bit word, but the byte-to-bit mapping changes across the `0x1C1B0A80100000` threshold:

- older layout:
  - `flag_04` -> bits `0x0000FF00`
  - `flag_05` -> bits `0x000000FF`
  - `flag_06` -> bits `0x00FF0000`
- newer layout:
  - `flag_04` -> bits `0x00FF0000`
  - `flag_05` -> bits `0x000000FF`
  - `flag_06` -> bits `0xFF000000`

The same setter also feeds the legacy code-sign / task-patching helpers:

- `flag_06` is propagated into the extra dyld/task flag path (`sub_2F194`, `sub_3B49C`)
- `flag_05` is also propagated into the legacy code-sign helper path

Recovered `0x80000` call sites make this less speculative:

- `sub_A1E0` does a `0xC000001B` probe, then a `0x4000001B` set on `mach_task_self_`
- that helper leaves `flag_04 = 0`, `flag_05 = 0`, and sets `flag_06 = 1` only when `dyldVersionNumber >= 900.0`
- `sub_24B78` repeats the same `0xC000001B` -> `0x4000001B` sequence before, on `hw.cpufamily == 458787763`, issuing selector `0x40000010` with an entitlement plist that grants:
  - `IOSurfaceRootUserClient`
  - `AGXDeviceUserClient`

That makes `0x4000001B` a real prerequisite task-policy/code-sign mutation step, not just a vague internal toggle.

### Terminal Helper Families

The tail of the native chain is also more concrete now. The per-kernel branch at the end of `sub_3CCA8` / `sub_3D1AC` is not a single opaque patch helper; it is a family of mailbox/publication routines selected by kernel-address thresholds and state bits.

Recovered 17.x families:

- `sub_1DBD8` / older modern equivalent
  - fileport/voucher mailbox graft helper
  - uses keyed handle lookup from `0x1122334455667788 + n`
  - converts saved FDs into fileports and writes `a1+6608` plus `a1+6624` / `a1+536` derived values into recovered slot structures
- `sub_1DE68`
  - memory-entry handoff helper
  - uses voucher recipes keyed from `0x3122334455667788 + n`
  - builds a one-page control block containing `{ a1+6608, a1+240, a1+264, a1+272 }`
  - publishes three handles through recovered mailbox slots
- `sub_1E154`
  - newer-build slot handoff
  - uses `sub_1CA68()` mailbox slots `0` and `1`
  - exports `{ a1+6608, a1+6296, a1+6304, a1+128, a1+136, a1+160, a1+168 }`
  - finalizes through `sub_28BD8`
- `sub_C060`
  - highest branch when `(*(_BYTE *)state & 0x20) != 0`
  - builds a control page, calls `sub_BE50` to derive three extra ports/handles, then publishes them through mailbox slots `21`, `22`, `24`, and `25`
  - those slot ids come directly from `xmmword_436A0`

The branch ladder is selected from:

- kernel-address thresholds:
  - `0x1F5418FFFFFFFF`
  - `0x225C19804FFFFF`
  - `0x225C1E804FFFFF`
  - `0x27120F04B00002`
- state bits:
  - `(*(_DWORD *)state & 0x5584001)`
  - `(*(_BYTE *)state & 0x20)`

The two modern `0x90000` variants checked here, `377bed...` and `7a1cef...`, preserve the same selector contract and the same helper-family split even though the concrete function addresses move.

### What This Means

The `0x90000` record is not a one-shot payload runner. It acts as a kernel primitive / service object for the later native stages.

The most defensible description from the recovered code is:

- it uses Mach memory-entry and port spray setup
- pivots through `IOSurfaceRoot`
- then patches kernel-resident sandbox / AMFI / developer-mode policy state

### Public Family Correlation

The public-family label is narrower now:

- it is not a good match for public KFD-style descriptions
  - the recovered code is built around `IOGPU` / `AGXG`, `IOSurfaceRoot`, and `__PPLTEXT` scanning, not the public KFD PUAF/weightBufs patterns
- it is not a good match for the public `oobPCI` sources in Fugu17
  - primary-source comparison against Fugu17’s public `Exploits/oobPCI` code does not show the `AGXG`, `IOSurfaceRoot`, or `IOServicePublish` / `IOServiceSetAuthorizationID` markers recovered here

The most defensible label from code facts is:

- a custom IOGPU / AGX + IOSurface + PPL-aware kernel exploit framework

That is more precise than calling it merely “unknown”, and more defensible than forcing an unsupported public-family name.

## `0xF0000`: Live TweakLoader Contract

Exports from `TweakLoader.dylib`:

- `_last`
- `_end`
- `_dyld_lv_bypass_init`
- `_save_actual_dylib`
- `_save_section_to_file`
- `_builtin_vm_protect`
- `_pacia`

Important mechanics:

- `_last` resolves `dlsym`, thread helpers, file helpers, then calls `save_actual_dylib()`.
- `save_actual_dylib()` extracts `__TEXT,__SBTweak` to `/tmp/actual.dylib`.
- `_dyld_lv_bypass_init()` resolves:
  - `printf`
  - `__fcntl`
  - `__mmap`
  - `task_info`
  - `mach_task_self_`
  - `dlopen`
  - `dlerror`
  - `munmap`
  - `mprotect`
  - `exit`
- `_init_bypassDyldLibValidation()` scans dyld for hook signatures and patches dyld’s `mmap` / `fcntl` paths.
- There is also a Dopamine-specific fallback path that locates a syscall hook site and redirects it.
- After patching dyld, it does:
  - `dlopen("/tmp/actual.dylib", RTLD_NOW)`
  - resolve `next_stage_main`

So the outer `0xF0000` contract is:

- valid Mach-O / FAT image
- export `_last` or `_end`

The inner embedded payload contract is:

- export `next_stage_main`

## Embedded `__SBTweak`

Extracted from:

- `live-site/TweakLoader/.theos/obj/arm64e/TweakLoader.dylib`
- section `__TEXT,__SBTweak`
- size `0x18590`

Recovered exports:

- `_next_stage_main`
- `_start`
- `_startl`
- `_startm`
- `_startr`

Recovered classes and functions:

- `PWNLockscreenOverlayView`
- `PWNBootstrap`
- `PWNScheduleHookInstall`
- `PWNInstallLockscreenHooks`
- `PWNHookedViewDidAppear`
- `PWNHookedViewDidDisappear`
- `PWNHookedViewDidLayoutSubviews`

### Behavior

`next_stage_main()` just calls `PWNBootstrap()`.

`PWNBootstrap()` runs a `dispatch_once` block and schedules lockscreen hook installation.

`PWNInstallLockscreenHooks()` iterates a class-name list and swizzles:

- `viewDidAppear:`
- `viewDidDisappear:`
- `viewDidLayoutSubviews`

Observed target controller names:

- `CSCoverSheetViewController`
- `SBDashBoardViewController`
- `SBDashBoardMainPageViewController`
- `SBLockScreenViewControllerBase`

The hook implementations:

- install the overlay on appear
- remove it on disappear
- keep it frontmost on layout

The overlay text is explicit:

- `LOCKSCREEN COMPROMISED`
- `PWNED`
- `Coruna custom lockscreen module active`
- `Swipe up to unlock. Visual marker only.`

That makes the embedded payload a visible user-interface marker rather than a stealth implant.


## Offline Reproduction

```bash
# Build a Stage3 container
python3 tools/coruna_payload_tool.py build-container \
  --manifest live-site/payloads/manifest.json \
  --payload-root live-site/payloads \
  --hash-name 377bed7460f7538f96bbad7bdc2b8294bdc54599 \
  --emulate-live-stage3 --has-pac \
  --output /tmp/377bed.container

# Extract embedded __SBTweak
python3 tools/coruna_payload_tool.py list-sections \
  live-site/TweakLoader/.theos/obj/arm64e/TweakLoader.dylib \
  --arch arm64e

python3 tools/coruna_payload_tool.py extract-section \
  live-site/TweakLoader/.theos/obj/arm64e/TweakLoader.dylib \
  --segment __TEXT --section __SBTweak \
  --output /tmp/actual_arm64e.dylib

# Inspect small records
python3 tools/coruna_payload_tool.py inspect-record \
  live-site/payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry6_type0x07.bin

python3 tools/coruna_payload_tool.py inspect-record \
  live-site/payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry3_type0x07.bin
```

`--emulate-live-stage3` matches live Stage3 behavior by rewriting `entry2_type0x0f.dylib` to local `TweakLoader.dylib` and, on trimmed mirrors, backfilling missing `entry1_type0x0a.bin` from a deterministic in-tree fallback copy.

## Clean-Room Source

```
clean-room/
  include/coruna_contracts.h       recovered ABI: record IDs, structs, vtable layouts
  include/coruna_stage_loader.h    loader-side record-store and worker-pack contracts
  src/coruna_contracts.c           validation helpers, record-store logic
  src/coruna_stage_loader.c        dedup/conflict logic, mode projection, worker-pack builder
```

```sh
clang -std=c11 -Wall -Wextra -Werror -Iclean-room/include -fsyntax-only \
  clean-room/src/coruna_contracts.c clean-room/src/coruna_stage_loader.c
python3 -m py_compile tools/coruna_payload_tool.py
```

## Clean-Room Build Order

1. Re-implement Stage1 with the unified memory-primitive surface.
2. Re-implement Stage2 so it consumes only that surface and returns PAC helpers.
3. Rebuild Stage3 around manifest/container/shared-buffer semantics, not the original malware control flow.
4. Recreate `bootstrap.dylib` record handling and selector logic with clean names and structs.
5. Recreate `0x50000` and `0x90001` as the auxiliary helper path for environments that need the inherited/executable mapping branch.
6. Recreate `0x80000`, `0x90000`, and `0xF0000` as separately readable projects.
7. Keep the visible `sbtweak.m` payload benign and explicit so the end state stays demonstrable.


## Current Secondary Questions

The `0x50000`, `prefix32`, `0xA0000`, and optional module questions are substantially narrowed above. The `prefix32` sideband is now traced: `sub_6BA0` in the `0x80000` image composes it with the selected-path string and writes the result back into the record store for downstream native consumption.

Remaining lower-priority unknowns:

- records `0x10000`, `0x30000`, `0x40000` are now confirmed as configuration-dependent and absent from `manifest.json`. Their runtime origin is still untraced.
- `_startx` and `_starti` are additional dispatch targets whose handling is path-specific. When their backing records exist, the `0x80000` image loads and calls them; when absent, the resulting errors are handled by the surrounding call sites rather than by a single universal “optional module” path.
- the `platform_module.js` version offset table maps specific iOS builds to internal offset keys, but the mapping between those keys and the native chain's kernel-version thresholds has not been cross-referenced
- the three state-inheritance trigger functions (`sub_9DC8`/`sub_13C5C`/`sub_1393C`) are now fully traced — they inherit pre-published kernel state via voucher recipes and shared memory
- the initial kernel address leak mechanism is now traced: `sub_72EC` uses the IOSurface `kIOSurfaceMemoryRegion` property to control backing store allocation, then scans kernel memory through the surface's userclient interface
- the vulnerability class is now identified: IOSurface/IOGPU info leak → pmap permission escalation. `sub_F1F8` is a verification scanner (not the corruption), `sub_F07C` validates IOKit heap structures, and the actual pmap writes happen in the `sub_8A48` main body after the target IOSurface kernel object is located
- the exact IOSurface userclient selector used for the initial kernel heap read (inside `sub_719C`) and the specific `IOConnectCallMethod` parameters that trigger the controlled allocation have not been fully decomposed, but the mechanism is clear

Resolved chain shape:

- Stage1 gets JS R/W
- Stage2 gets PAC-aware sign/auth/call
- Stage3 rebuilds and serves `0xF00DBEEF` bundles
- bootstrap picks the right hash and dispatches by `f1`
- `0x90001` controls the helper mapping path, publishes the raw `0x50000` helper region, and adjusts `vm_map` / `pmap` state for it
- `0x80000._start` resolves `_driver` from `0x90000` and hands off to `_startl`
- `_startl` spawns a worker thread that registers string records and calls `sub_7410`
- `sub_7410` injects entitlements, suppresses exception guards, invokes `_startsc` from `0xA0000` for cleanup, dispatches `_startr`, and performs additional crash-report deletion
- `_startr` reads the `0x70005` mode record and continues into `sub_6BA0`
- `sub_6BA0` propagates the `prefix32` sideband into the record store, resolves `_startx` from `0x10000`, and dispatches it
- `0x90000` builds kernel-level access and patches policy state
- `0xF0000` loads `TweakLoader`
- `TweakLoader` extracts and runs the embedded visible lockscreen payload
