# Coruna Full Exploit Reconstruction

## Scope

This document reconstructs the exploit chain as it exists in the live mirror under `live-site/`, with emphasis on showing how the chain actually works end to end instead of only annotating isolated RE fragments.

The standalone published repo does not include that `live-site/` mirror or `EXPLOIT_CHAIN_WRITEUP.md`. References to those files are provenance notes from the original research workspace, not files available in this package. Those private materials were used to corroborate the browser/PAC/native chain shape here, but are intentionally excluded from the publication to avoid redistributing the original chain.

The reconstruction below is based on:

- `EXPLOIT_CHAIN_WRITEUP.md`
- `live-site/index.html`
- `live-site/Stage1_16.2_16.5.1_terrorbird.js`
- `live-site/Stage1_16.6_17.2.1_cassowary.js`
- `live-site/Stage2_16.3_16.5.1_seedbell.js`
- `live-site/Stage2_16.6_17.2.1_seedbell_pre.js`
- `live-site/Stage2_17.0_17.2.1_seedbell.js`
- `live-site/Stage3_VariantB.js`
- `live-site/payloads/bootstrap.dylib`
- `live-site/payloads/<hash>/entry*.dylib`
- `live-site/TweakLoader/.theos/obj/arm64*/TweakLoader.dylib`

## Coverage Split

The coverage in this repo breaks down like this:

- **iOS 16 browser path:** `terrorbird` on `16.2–16.5.1`, then the older `seedbell` branch on `16.3–16.5.1`
- **iOS 17 browser path:** `cassowary` on `16.6–17.2.1`, then `seedbell_pre` plus the newer `seedbell` branch on `17.0–17.2.1`
- **Shared native path:** `Stage3_VariantB.js`, `bootstrap.dylib`, the `0x50000` helper, records `0x80000` / `0x90000` / `0x90001`, and `0xF0000` sit after browser exploitation and are largely shared across the documented range

Standalone-repo note: the omitted `live-site/` mirror and internal writeup carry much of the line-level provenance for the browser-stage material. The browser/PAC sections here were cross-checked against those private sources; the standalone publication simply does not re-ship them.

The remaining implementation gap is the deeper per-version `0x90000` state/patch logic, so the repo documents the iOS 17 browser chain already but does not yet present a source-equivalent 17.x-specific native exploit implementation.

## End-To-End Shape

The live chain is:

1. `index.html` fingerprints the device, chooses Stage1/Stage2/Stage3, and initializes `platformModule.platformState`.
2. Stage1 gets a JS arbitrary read/write primitive.
3. Stage2 converts the JS primitive into PAC-aware `sign/auth/call` primitives on arm64e.
4. Stage3 rebuilds a `0xF00DBEEF` record container from `payloads/manifest.json`, maps `bootstrap.dylib`, and jumps to `_process`.
5. `bootstrap.dylib` runs environment checks, spins up the background worker, and uses the JS/native shared buffer to request a payload bundle by hash.
6. Record `0x80000` is the orchestrator dylib. It resolves `0x90000` as `_driver`, obtains a vtable-backed driver object, then continues the native chain.
7. Record `0xF0000` is the live TweakLoader slot. In the live mirror, Stage3 rewrites it to local `TweakLoader.dylib`.
8. `TweakLoader.dylib` extracts its embedded `__TEXT,__SBTweak` Mach-O to `/tmp/actual.dylib`, patches dyld lib-validation, `dlopen`s the extracted Mach-O, and calls its exported `next_stage_main`.
9. The embedded `__SBTweak` installs lockscreen/SpringBoard hooks and draws a visible “LOCKSCREEN COMPROMISED / PWNED” overlay.

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

This is the anti-analysis gate:

- `stat("/usr/libexec/corelliumd")`
- `sandbox_check(..., "iokit-get-properties", ...)`
- IOKit serial-number checks against `CORELLIUM`
- CPU capability / VM heuristics

It returns a single-byte environment verdict via the caller-supplied pointer.

### `sub_987C` at `0x987c`

This is the JS/native downloader bridge:

- waits on a semaphore
- writes the primary request string at full-buffer offset `+0x4` (`bytes + 0x0` once the leading opcode dword is skipped)
- optionally writes a secondary string at full-buffer offset `+0x800000` (`bytes + 0x7ffffc`)
- flips the request opcode to `1` or `7`
- busy-waits until JS answers with opcode `3` or `4`
- on success, copies `size` from full-buffer offset `+0x4` and payload bytes from `+0x8` (`bytes + 0x0` / `bytes + 0x4`)

That matches `Stage3_VariantB.js:wA()` and `feedRawBuffer()` exactly.

### `sub_9CB8` at `0x9cb8` and `sub_9F18` at `0x9f18`

These parse the raw `0x12345678` selector record and choose the right payload hash for the current environment.

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

That makes `prefix32` best described as opaque per-selected-payload sideband metadata for the native stages. It is not part of selector matching, it is not a plain filename or file-content digest, and the visible JS/runtime side does not use it as decryption or verification material.

### `sub_8430` at `0x8430`

This is the LZMA decompressor:

- header magic `0x0BEDF00D`
- decoded with `_compression_decode_buffer`

### `sub_6C44` and `sub_5FEC`

The worker and setup path do the post-bootstrap setup:

- background task registration through `UIApplication`
- optional SIGSEGV wrapper for some branches
- fetch record `0x70000`
- decide between direct inherited mappings and a helper mapping path
- fetch and activate record `0x80000`
- continue into the orchestrator dylib

## Record Contracts

The stable record IDs in the modern payload sets are:

- `0x70000`
- `0x70005`
- `0x50000`
- `0x80000`
- `0x90000`
- `0x90001`
- `0xF0000`

The filename is secondary after Stage3 rebuilds the container. `f1` is the real contract.

Resolved role split:

- `0x50000` is a raw arm64 helper loader blob used only on the auxiliary bootstrap path.
- `0x90000` is the main post-exploit driver object resolved by `0x80000`.
- `0x90001` is a transient helper-driver object used by bootstrap to control `0x50000`.

## `0x50000` And `0x90001`: Auxiliary Bootstrap Helper Path

This pair is only used in the fallback/helper mapping branch inside `bootstrap.dylib:sub_5FEC`.

### `0x90001`

`0x90001` (`entry5_type0x09.dylib`) exports `_driver` just like `0x90000`, but bootstrap uses it differently.

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

So `0x90001` is not the main exploit service object. It is the bootstrap-time control plane for the helper mapping path.

### `0x50000`

`0x50000` (`entry4_type0x05.bin`) is raw arm64 position-independent code. It is not a plain data blob, and it is not a stripped Mach-O.

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
- `ctx + 0x38` is called with that handle and the string `"_start"` to resolve the orchestrator entrypoint
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

That makes `0x50000` best described as a flat manual-loader/runtime module with syscall veneers and embedded loader metadata. In live use it is not just a helper-control blob: bootstrap installs it, uses it to load record `0x80000`, resolves `_start`, executes that entrypoint, and then unloads the temporary loaded image.

### IPSW / Firmware Correlation For The Helper Path

The 17.0.3 IPSW-derived dyld and XNU artifacts tighten the exact role of this branch:

- `bootstrap.dylib:sub_5FEC` calls `task_info(mach_task_self_, TASK_DYLD_INFO, ...)` and reads `all_image_info_addr`
- it then reaches `dyld_all_image_infos + 0x28`, which is `jitInfo` in the public `dyld_all_image_infos` layout
- after the helper branch allocates the executable helper region and companion 16 MB data region, it stores the control pointer through that `jitInfo` slot

Primary-source backing:

- in 17.0.3 dyld, `dyld4::ExternallyViewableState::switchToDyldInDyldCache()` registers `_dyld_all_image_infos` via `proc_set_dyld_all_image_info(&dyld_all_image_infos, 368)`
- in XNU, `TASK_DYLD_INFO` returns only `all_image_info_addr`, `all_image_info_size`, and format from `task->all_image_info_*`
- XNU exec paths copy in the dyld anchor structure as metadata, but there is no 17.0.3 dyld or XNU path that operationally consumes `jitInfo`

That changes the precise interpretation:

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

Exports:

- `_start` at `0x8754`
- `_startl` at `0x8228`
- `_startr` at `0x8d90`
- `_startm` at `0x94dc`

Important mechanics:

- `_start` patches a set of callback slots in the copied bootstrap state.
- It resolves `_driver` from record `0x90000`.
- It calls `_driver` to obtain a vtable-backed interface object.
- It resolves `_startl` from record `0x80000` and passes the interface object into it.

So `_start` is the handoff from the bootstrap record store into the native driver/service object.

### `_startr`

`_startr` pulls record `0x70005` (`458757`) from the record store, expects:

- minimum size `0x18`
- magic `0xDEADD00F`

and then uses byte offset `0x5` as the boolean mode flag, with the TTL dword coming from offset `0x8`, before continuing into `sub_8E84`.

Observed fields in the live `0x70005` blob after the magic. The blob we recovered is larger than the `0x18` minimum accepted by `_startr`:

- raw flags dword at offset `0x4` with the enable bit read from byte `0x5`
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

## `0x90000`: Driver-Facade Dylib

Export:

- `_driver` at `0x5ec4`

`_driver` allocates a `0x50`-byte vtable-backed object and installs these methods:

- `sub_5F9C`: destructor/free
- `sub_5FDC`: create/init state object via `sub_3E42C`
- `sub_608C`: validation / refresh path
- `sub_6030`: main dispatcher wrapper around `sub_3E580`
- `sub_6070`: teardown/release helper
- `sub_60A8`: read a cached status field at offset `+6424`
- `sub_60EC`: batch dispatcher over a list of operations
- `sub_6224`: query kernel version triple

### `sub_3E42C`

`sub_3E42C`:

- allocates a `0x1d60` state object
- initializes it via `sub_3CCA8`
- probes mount/update state via `sub_13EBC` and records the result into the object
- returns the initialized object

### `sub_3E580`

This is the actual heavy native exploit/primitive builder. The important behavior is clear even though the function is large.

Observed mechanics:

1. Environment and version gate:
   - records kernel version / build
   - rejects Corellium / unsupported environments
   - derives feature flags from the OS / device class

2. Mach memory-entry staging:
   - `vm_allocate`
   - `mach_make_memory_entry`
   - `vm_map`
   - `madvise`
   - large port spray with `mach_port_allocate` and raised queue limits

3. IOSurface pivot:
   - `IOServiceGetMatchingService("IOSurfaceRoot")` style path via `sub_24D64("IOSurfaceRoot")`
   - repeated `IOServiceOpen` calls to acquire userclients
   - `dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", ...)`
   - resolve `kIOSurfaceIsGlobal`, `kIOSurfaceWidth`, `kIOSurfaceHeight`
   - build a serialized IOSurface create dictionary
   - call `IOConnectCallMethod(..., selector 0, ...)`

4. Kernel pointer harvesting / primitive build:
   - inspects returned object fields and alignment conditions
   - derives kernel pointers and region bounds
   - builds reusable read/write state for later helpers

5. Policy / entitlement patching after primitive build:
   - looks up `com.apple.security.sandbox`
   - looks up `com.apple.driver.AppleMobileFileIntegrity`
   - resolves `developer_mode_status`
   - resolves `allows_security_research`
   - patches those fields when they are not already enabled
   - carries a baked entitlement plist fragment for `task_for_pid-allow`

6. Special-port and task escalation:
   - obtains host-related ports
   - resolves additional kernel handles
   - finalizes task / host access paths before returning success

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
  - uses `host_create_mach_voucher` recipes keyed from `0x1122334455667788 + n`
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

The `0x90000` record is not a one-shot payload runner. It is a kernel primitive / post-exploit service object.

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

## Clean Offline Reproduction

To reproduce the native payload chain offline without the browser exploit:

1. Rebuild the Stage3 output blob from `manifest.json` (usually a `0xF00DBEEF` container, but some manifest entries are raw passthrough blobs).
2. Extract `__TEXT,__SBTweak` from `TweakLoader.dylib`.
3. Inspect exported symbols from the extracted Mach-O with standard external Mach-O tooling.

The helper script added in `tools/coruna_payload_tool.py` covers step 1, step 2, and small-record inspection. Export-symbol inspection in step 3 still relies on external tooling, and the examples below require the original `live-site/` mirror that is not included in this standalone repo.

Examples:

```bash
python3 tools/coruna_payload_tool.py build-container \
  --manifest live-site/payloads/manifest.json \
  --payload-root live-site/payloads \
  --hash-name 377bed7460f7538f96bbad7bdc2b8294bdc54599 \
  --emulate-live-stage3 \
  --has-pac \
  --output /tmp/377bed.f00dbeef
```

```bash
python3 tools/coruna_payload_tool.py extract-section \
  live-site/TweakLoader/.theos/obj/arm64e/TweakLoader.dylib \
  --segment __TEXT \
  --section __SBTweak \
  --output /tmp/actual_arm64e_from_section.dylib
```

```bash
python3 tools/coruna_payload_tool.py list-sections \
  live-site/TweakLoader/.theos/obj/arm64e/TweakLoader.dylib
```

```bash
python3 tools/coruna_payload_tool.py inspect-record \
  live-site/payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry6_type0x07.bin
```

```bash
python3 tools/coruna_payload_tool.py inspect-record \
  live-site/payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry3_type0x07.bin
```

## Current Secondary Questions

The previously open `0x50000` and `prefix32` questions are narrowed substantially above. The remaining lower-priority unknowns are narrower:

- what native consumer ultimately interprets the forwarded `prefix32` sideband after Stage3 concatenates it into the generated payload buffer
- whether later stages load any additional optional modules beyond the confirmed `0x50000 -> 0x80000 -> _start -> unload` cycle

None of those currently change the main chain shape reconstructed here:

- Stage1 gets JS R/W
- Stage2 gets PAC-aware sign/auth/call
- Stage3 rebuilds and serves `0xF00DBEEF` bundles
- bootstrap picks the right hash and dispatches by `f1`
- `0x90001` controls the helper mapping path, publishes the raw `0x50000` helper region, and adjusts `vm_map` / `pmap` state for it
- `0x80000` resolves `_driver` and `_last/_end`
- `0x90000` builds kernel-level post-exploit access and patches policy state
- `0xF0000` loads `TweakLoader`
- `TweakLoader` extracts and runs the embedded visible lockscreen payload
