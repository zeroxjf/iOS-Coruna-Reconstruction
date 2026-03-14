# Coruna Clean-Room Blueprint

This document converts the recovered chain into implementation-facing contracts so the exploits can be rebuilt as clean, readable modules instead of reusing the original malware packaging.

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

2. `stage2_pac.js`
   Consumes the Stage1 primitive and produces:
   - `pacia`
   - `pacda`
   - `autia`
   - `autda`
   - PAC-aware indirect call helpers

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

## Small Record Formats

### Selector Blob (`entry6_type0x07.bin`)

Recovered from `bootstrap.dylib:sub_9F18` and the live payloads:

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
    uint8_t prefix32[32];  // opaque sideband, forwarded separately as request 0x70002
    char filename[64];     // e.g. "4612aa...min.js"
};
```

Observed 17.0.3 example:

- `base_path = "./"`
- `count = 2`
- record 0:
  - `selector_key = 0x02900000`
  - `prefix32 = 85ab5908ceb1981df3449b52155a5026561c51d6f9f599acc99c5203b14733eb`
  - `filename = "4612aa650e60e2974a9ec37bbf922c79635b493a.min.js"`
- record 1:
  - `selector_key = 0xE2900000`
  - `prefix32 = b252669de4b4adc34114fdf10d75f66b3efad6280f4fcd19603f6fac5873ede2`
  - `filename = "4817ea8063eb4480e915f1a4479c62ec774f52ce.min.js"`

Observed behavior to preserve in a clean-room rebuild:

- selection is done only on `selector_key`
- `base_path + filename` is sent on request `0x70001`
- `prefix32` is sent separately on request `0x70002`
- the older 17.0.3 web loader uses the salt `cecd08aa6ff548c2` and derives fetch names as `sha256(salt + module_id).substring(0, 40) + ".js"`
- that older loader executes the fetched body directly with `new Function(...)`; there is no visible JS decrypt step or MAC/checksum verification
- Stage3 carries `prefix32` unchanged as `fixedValue2` / `cA` and concatenates it into the native payload buffer
- the older salted loader proves `prefix32` is not the original module name, and recovered payload hashes prove it is not a direct digest of the saved `.min.js` bytes

Clean-room interpretation:

- treat `prefix32` as opaque native-side sideband data
- do not assign it selector, decrypt, or verifier semantics in the JS stage unless later native RE proves that

### Mode / Target Blob (`entry3_type0x07.bin`)

Recovered from `_startr` plus the live blob layout:

```c
struct ModeBlobObserved {
    uint32_t magic;          // 0xDEADD00F
    uint32_t raw_flags_04;   // `_startr` later reads byte 5 as boolean
    uint32_t ttl_seconds;    // observed 0x15180
    uint32_t field_0c;       // observed 0x7d0
    uint32_t field_10;       // observed 1
    uint32_t field_14;       // observed 1
    uint32_t field_18;       // observed 2
    uint32_t string_offset;  // observed 0x24
    uint32_t string_length;  // observed 0x0c
    char payload_name[];     // "SpringBoard"
};
```

The only fields used directly by `_startr` in the recovered path are the enable byte at `+0x5` and the TTL dword at `+0x8`, but the remainder should be preserved when reproducing the live bundle.

## Native Record Responsibilities

### `0x80000`

- export `_start`, `_startl`, `_startr`, `_startm`
- resolve `_driver` from record `0x90000`
- instantiate driver object
- resolve `_startl` from itself
- fetch and validate `0xF0000`
- resolve `_last` or `_end` from `0xF0000`

### `0x90000`

- export `_driver`
- return a `0x50`-byte object with method pointers
- large internal path builds the kernel primitive using:
  - Mach memory-entry staging
  - port spray
  - `IOSurfaceRoot`
  - post-primitive sandbox / AMFI / developer-mode policy patching

### `0x90001`

- export `_driver`
- return a second `0x50`-byte helper object
- bootstrap uses only these methods:
  - create session
  - dispatch command
  - destroy session
- used only on the auxiliary helper mapping path before `0x80000` takes over

### `0x50000`

- raw arm64 PIC blob, not a plain data record
- publishes three internal function pointers from its init stub into the bootstrap context
- contains syscall veneers at the front
- implements an in-memory FAT/Mach-O loader used by the helper path
- is copied into an executable helper region with a companion 16 MB data mapping
- bootstrap publishes that helper region through `dyld_all_image_infos.jitInfo`
- the 17.0.3 IPSW-backed model is “helper rendezvous/control page”, not “dyld executes this blob for us”
- the copied entry stub installs:
  - `ctx + 0x30`: load external image bytes
  - `ctx + 0x38`: resolve a symbol from a loaded image
  - `ctx + 0x130`: unload/finalize a loaded image
- bootstrap immediately uses those installed callbacks through wrapper slots at `ctx + 0xF8`, `ctx + 0x100`, and `ctx + 0x108`
- the observed live sequence is:
  - load record `0x80000` through `ctx + 0x30`
  - recover the loaded-image handle through `ctx + 0x108`
  - resolve `"_start"` through `ctx + 0x38`
  - call that `_start(ctx)`
  - unload the temporary `0x80000` handle through `ctx + 0x100`

### `0xF0000`

- must be Mach-O or FAT
- must export `_last` or `_end`
- current live implementation:
  - extracts embedded `__TEXT,__SBTweak`
  - patches dyld validation path
  - `dlopen`s `/tmp/actual.dylib`
  - expects `next_stage_main`

## Offline Reconstruction Workflow

The helper script in `tools/coruna_payload_tool.py` is enough to reproduce the live container and inspect the small records:

```bash
python3 tools/coruna_payload_tool.py build-container \
  --manifest live-site/payloads/manifest.json \
  --payload-root live-site/payloads \
  --hash-name 377bed7460f7538f96bbad7bdc2b8294bdc54599 \
  --emulate-live-stage3 \
  --has-pac \
  --output /tmp/377bed.container

python3 tools/coruna_payload_tool.py inspect-record \
  live-site/payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry6_type0x07.bin

python3 tools/coruna_payload_tool.py inspect-record \
  live-site/payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry3_type0x07.bin
```

## Clean-Room Build Order

1. Re-implement Stage1 with the unified memory-primitive surface.
2. Re-implement Stage2 so it consumes only that surface and returns PAC helpers.
3. Rebuild Stage3 around manifest/container/shared-buffer semantics, not the original malware control flow.
4. Recreate `bootstrap.dylib` record handling and selector logic with clean names and structs.
5. Recreate `0x50000` and `0x90001` as the auxiliary helper path for environments that need the inherited/executable mapping branch.
6. Recreate `0x80000`, `0x90000`, and `0xF0000` as separately readable projects.
7. Keep the visible `sbtweak.m` payload benign and explicit so the end state stays demonstrable.
