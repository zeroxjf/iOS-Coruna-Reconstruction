# iOS-Coruna-Reconstruction

This repository packages reverse engineering notes, clean-room reconstruction work, and tooling for the Coruna exploit chain into a standalone handoff repo.

## Disclaimer

This repository was assembled primarily with Codex GPT-5.4 xhigh across multiple iterative passes — not a single one-shot generation. Each pass refined and cross-checked the previous output against disassembly, decompilation, and known chain behavior, but the results are still AI-assisted inferences. There may be mistakes, omissions, or misinterpretations. Verify offsets, structures, control flow, primitives, and behavioral conclusions against the original binaries, firmware images, and live test devices before relying on any part of it.

## Scope

The focus here is reconstructing the exploit chain without the original malware packaging and delivery behavior.

Current status:

- strong RE dossier for the chain shape and record formats
- compile-checked clean-room contracts and loader-side helper code
- supporting tooling for payload inspection and container rebuilds
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
  - helper for payload/container inspection and rebuilds

## Verification

From the repo root:

```sh
clang -std=c11 -Wall -Wextra -Werror -Iclean-room/include -fsyntax-only \
  clean-room/src/coruna_contracts.c \
  clean-room/src/coruna_stage_loader.c

python3 -m py_compile tools/coruna_payload_tool.py
```
