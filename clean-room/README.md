# Clean-Room Contracts

This directory is the start of a source-equivalent handoff tree.

Current scope:

- `include/coruna_contracts.h`
  - recovered record IDs, including auxiliary `0x70001/03/04/05/06` and optional `0xA0000`
  - `0xF00DBEEF` container header and entry layout
  - `0x70000` selector blob layout
  - `0x70005` mode blob view with the enable bit at byte `+0x5` and TTL dword at `+0x8`
  - bootstrap callback slot offsets used by `0x50000`
  - `0x90000` and `0x90001` vtable object layouts
  - helper command IDs observed on the live `0x90001` path
- `src/coruna_contracts.c`
  - validation helpers for the selector and mode blobs
  - thin wrappers around the recovered `0x90000` and `0x90001` method tables
- `include/coruna_stage_loader.h`
  - fixed-size stage slot layout consumed by the `0x80000` record-store builder
  - default mode TTL/state projection used by `_startr`
  - exact `0x80000` thread-pack initialization contract
- `src/coruna_stage_loader.c`
  - record-store dedup/conflict logic matching `sub_25020`
  - `0x70005` mode status projection with the live 86400-second default
  - clean-room helpers for building the worker thread pack handed to `sub_94E8`

Recovered live sequence represented by these contracts:

1. Stage3 rebuilds a `0xF00DBEEF` container.
2. Bootstrap selects a `0x70000` record and forwards `prefix32` as opaque sideband data.
3. Bootstrap helper path loads `0x50000`, which installs:
   - `ctx + 0x30`: load image
   - `ctx + 0x38`: resolve symbol
   - `ctx + 0x130`: unload image
4. Bootstrap uses those installed callbacks to load `0x80000`, resolve `"_start"`, call it, and unload the temporary image.
5. `0x80000` resolves `0x90000::_driver`, instantiates the driver object, and passes it into `_startl`.
6. `_startl` builds a 24-slot record store, injects `0x70003/0x70004` string records, optionally carries `0x70006`, and spawns the worker pack consumed by `sub_94E8`.
7. The worker consults `0x70005` for mode/TTL and may invoke the optional `0xA0000::_startsc` path before the main `_startr` flow.

The remaining work is to replace these ABI-level contracts with clean source implementations for:

- `bootstrap.dylib`
- the `0x50000` loader/runtime
- the `0x80000` orchestrator
- the `0x90000` kernel exploit / policy patch path
- the `0xF0000` final-stage loader
