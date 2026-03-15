#!/usr/bin/env python3

import argparse
import json
import pathlib
import struct
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
LC_SEGMENT_64 = 0x19

CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0x0
CPU_SUBTYPE_ARM64E = 0x2
ENTRY2_REWRITE_NAME = "entry2_type0x0f.dylib"


@dataclass
class SliceInfo:
    offset: int
    size: int
    arch_name: str


@dataclass
class SectionInfo:
    segment: str
    section: str
    addr: int
    size: int
    offset: int


@dataclass
class ResolvedEntry:
    manifest_file: str
    source_path: pathlib.Path
    actual_size: int
    manifest_size: Optional[int]
    rewritten: bool


def normalize_name(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def decode_c_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def cpu_name(cpu_type: int, cpu_subtype: int) -> str:
    masked_subtype = cpu_subtype & 0xFFFFFF
    if cpu_type == CPU_TYPE_ARM64:
        if masked_subtype == CPU_SUBTYPE_ARM64E:
            return "arm64e"
        if masked_subtype == CPU_SUBTYPE_ARM64_ALL:
            return "arm64"
        return f"arm64-subtype-{masked_subtype}"
    return f"cpu-{cpu_type:#x}-subtype-{masked_subtype:#x}"


def select_slice(data: bytes, wanted_arch: Optional[str]) -> SliceInfo:
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        is_64 = magic_be == FAT_MAGIC_64
        header_fmt = ">II"
        arch_fmt = ">IIIII" if not is_64 else ">IIQQII"
        header_size = struct.calcsize(header_fmt)
        arch_size = struct.calcsize(arch_fmt)
        _, count = struct.unpack_from(header_fmt, data, 0)
        slices: List[SliceInfo] = []
        for index in range(count):
            fields = struct.unpack_from(arch_fmt, data, header_size + index * arch_size)
            cpu_type, cpu_subtype = fields[0], fields[1]
            offset = fields[2]
            size = fields[3]
            arch_name = cpu_name(cpu_type, cpu_subtype)
            slices.append(SliceInfo(offset=offset, size=size, arch_name=arch_name))
        if wanted_arch:
            for candidate in slices:
                if candidate.arch_name == wanted_arch:
                    return candidate
            available = ", ".join(slice_info.arch_name for slice_info in slices)
            raise ValueError(f"arch {wanted_arch!r} not present; available: {available}")
        return slices[0]
    return SliceInfo(offset=0, size=len(data), arch_name="thin")


def iter_sections(data: bytes, slice_info: SliceInfo) -> Iterable[SectionInfo]:
    base = slice_info.offset
    magic_le = struct.unpack_from("<I", data, base)[0]
    magic_be = struct.unpack_from(">I", data, base)[0]
    if magic_le == MH_MAGIC_64:
        endian = "<"
    elif magic_be == MH_CIGAM_64:
        endian = ">"
    else:
        raise ValueError("unsupported Mach-O slice: expected 64-bit Mach-O")

    header_fmt = endian + "IiiIIIII"
    _, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(header_fmt, data, base)
    cursor = base + struct.calcsize(header_fmt)
    commands_end = cursor + sizeofcmds
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + "II", data, cursor)
        if cmd == LC_SEGMENT_64:
            seg_fields = struct.unpack_from(endian + "II16sQQQQiiII", data, cursor)
            segname = normalize_name(seg_fields[2])
            nsects = seg_fields[9]
            section_cursor = cursor + struct.calcsize(endian + "II16sQQQQiiII")
            for _section_index in range(nsects):
                sect_fields = struct.unpack_from(endian + "16s16sQQIIIIIIII", data, section_cursor)
                sectname = normalize_name(sect_fields[0])
                segname_from_section = normalize_name(sect_fields[1])
                addr = sect_fields[2]
                size = sect_fields[3]
                offset = sect_fields[4]
                yield SectionInfo(
                    segment=segname_from_section or segname,
                    section=sectname,
                    addr=addr,
                    size=size,
                    offset=offset,
                )
                section_cursor += struct.calcsize(endian + "16s16sQQIIIIIIII")
        cursor += cmdsize
        if cursor > commands_end:
            raise ValueError("load command parsing ran past command table")


def extract_section(data: bytes, slice_info: SliceInfo, segment: str, section: str) -> Tuple[SectionInfo, bytes]:
    for info in iter_sections(data, slice_info):
        if info.segment == segment and info.section == section:
            file_offset = slice_info.offset + info.offset
            return info, data[file_offset:file_offset + info.size]
    raise ValueError(f"section {segment},{section} not found")


def parse_manifest(manifest_path: pathlib.Path) -> dict:
    try:
        return json.loads(manifest_path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"manifest not found: {manifest_path}") from exc


def default_tweakloader_root(payload_root: pathlib.Path) -> pathlib.Path:
    return payload_root.parent.parent / "TweakLoader" / ".theos" / "obj"


def resolve_entry_path(
    payload_root: pathlib.Path,
    entry_file: str,
    emulate_live_stage3: bool,
    has_pac: bool,
    tweakloader_root: Optional[pathlib.Path],
) -> Tuple[pathlib.Path, bool]:
    if emulate_live_stage3 and entry_file == ENTRY2_REWRITE_NAME:
        root = tweakloader_root or default_tweakloader_root(payload_root)
        arch_dir = "arm64e" if has_pac else "arm64"
        rewritten = root / arch_dir / "TweakLoader.dylib"
        if not rewritten.exists():
            raise FileNotFoundError(
                f"live Stage3 rewrite target does not exist: {rewritten} "
                f"(pass --tweakloader-root in the standalone repo)"
            )
        return rewritten, True

    candidate = payload_root / entry_file
    if candidate.exists():
        return candidate, False

    if entry_file == ENTRY2_REWRITE_NAME:
        root = tweakloader_root or default_tweakloader_root(payload_root)
        arch_dir = "arm64e" if has_pac else "arm64"
        suggested = root / arch_dir / "TweakLoader.dylib"
        raise FileNotFoundError(
            f"{candidate} missing; use --emulate-live-stage3 to rewrite to {suggested} "
            f"(or pass --tweakloader-root in the standalone repo)"
        )

    raise FileNotFoundError(f"payload file not found: {candidate}")


def cmd_list_sections(args: argparse.Namespace) -> int:
    data = pathlib.Path(args.macho).read_bytes()
    slice_info = select_slice(data, args.arch)
    print(f"slice_arch={slice_info.arch_name} offset={slice_info.offset:#x} size={slice_info.size:#x}")
    for section in iter_sections(data, slice_info):
        print(
            f"{section.segment},{section.section} "
            f"addr={section.addr:#x} size={section.size:#x} fileoff={section.offset:#x}"
        )
    return 0


def cmd_extract_section(args: argparse.Namespace) -> int:
    macho_path = pathlib.Path(args.macho)
    data = macho_path.read_bytes()
    slice_info = select_slice(data, args.arch)
    section_info, section_bytes = extract_section(data, slice_info, args.segment, args.section)
    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(section_bytes)
    print(
        f"extracted {section_info.segment},{section_info.section} "
        f"size={section_info.size:#x} from {macho_path} "
        f"slice={slice_info.arch_name} -> {output_path}"
    )
    return 0


def build_f00dbeef_container(
    entries: list,
    payload_root: pathlib.Path,
    emulate_live_stage3: bool = False,
    has_pac: bool = False,
    tweakloader_root: Optional[pathlib.Path] = None,
    strict_manifest_sizes: bool = False,
) -> Tuple[bytes, List[ResolvedEntry]]:
    if len(entries) == 1 and entries[0].get("raw"):
        raw_path, rewritten = resolve_entry_path(
            payload_root,
            entries[0]["file"],
            emulate_live_stage3,
            has_pac,
            tweakloader_root,
        )
        raw_blob = raw_path.read_bytes()
        resolved = [
            ResolvedEntry(
                manifest_file=entries[0]["file"],
                source_path=raw_path,
                actual_size=len(raw_blob),
                manifest_size=entries[0].get("size"),
                rewritten=rewritten,
            )
        ]
        return raw_blob, resolved

    entry_blobs = []
    resolved_entries: List[ResolvedEntry] = []
    for entry in entries:
        source_path, rewritten = resolve_entry_path(
            payload_root,
            entry["file"],
            emulate_live_stage3,
            has_pac,
            tweakloader_root,
        )
        blob = source_path.read_bytes()
        declared = entry.get("size")
        if strict_manifest_sizes and declared is not None and declared != len(blob):
            raise ValueError(
                f"size mismatch for {entry['file']}: manifest={declared} actual={len(blob)}"
            )
        entry_blobs.append(blob)
        resolved_entries.append(
            ResolvedEntry(
                manifest_file=entry["file"],
                source_path=source_path,
                actual_size=len(blob),
                manifest_size=declared,
                rewritten=rewritten,
            )
        )

    header = bytearray()
    header += struct.pack("<II", 0xF00DBEEF, len(entries))
    data_offset = 8 + 16 * len(entries)
    body = bytearray()
    for entry, blob in zip(entries, entry_blobs):
        header += struct.pack(
            "<IIII",
            int(entry["f1"]),
            int(entry["f2"]),
            data_offset,
            len(blob),
        )
        body += blob
        data_offset += len(blob)
    return bytes(header + body), resolved_entries


def cmd_build_container(args: argparse.Namespace) -> int:
    manifest_path = pathlib.Path(args.manifest)
    payload_root = pathlib.Path(args.payload_root)
    manifest = parse_manifest(manifest_path)
    if args.hash_name not in manifest:
        available = ", ".join(sorted(manifest.keys())[:10])
        raise SystemExit(f"hash {args.hash_name!r} not found in manifest; examples: {available}")

    manifest_entries = manifest[args.hash_name]
    raw_passthrough = len(manifest_entries) == 1 and manifest_entries[0].get("raw")
    tweakloader_root = pathlib.Path(args.tweakloader_root) if args.tweakloader_root else None
    container, resolved_entries = build_f00dbeef_container(
        manifest_entries,
        payload_root / args.hash_name,
        emulate_live_stage3=args.emulate_live_stage3,
        has_pac=args.has_pac,
        tweakloader_root=tweakloader_root,
        strict_manifest_sizes=args.strict_manifest_sizes,
    )
    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(container)
    output_kind = "raw blob" if raw_passthrough else "F00DBEEF container"
    print(
        f"built {output_kind} hash={args.hash_name} size={len(container)} "
        f"entries={len(manifest_entries)} -> {output_path}"
    )
    for resolved in resolved_entries:
        notes = []
        if resolved.rewritten:
            notes.append("rewritten")
        if (
            resolved.manifest_size is not None
            and resolved.manifest_size != resolved.actual_size
        ):
            notes.append(
                f"WARNING manifest_size={resolved.manifest_size} actual_size={resolved.actual_size}"
            )
        note_text = f" [{' ; '.join(notes)}]" if notes else ""
        print(f"{resolved.manifest_file} -> {resolved.source_path}{note_text}")
    return 0


def cmd_inspect_record(args: argparse.Namespace) -> int:
    blob = pathlib.Path(args.path).read_bytes()
    if len(blob) < 4:
        raise ValueError("record too small to contain a magic")

    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic == 0x12345678:
        if len(blob) < 0x10C:
            raise ValueError("selector record too small")
        field_04 = struct.unpack_from("<I", blob, 4)[0]
        base_path = decode_c_string(blob[8:264])
        count = struct.unpack_from("<I", blob, 264)[0]
        print(
            f"kind=selector magic={magic:#x} field_04={field_04:#x} "
            f"base_path={base_path!r} count={count}"
        )
        cursor = 268
        for index in range(count):
            if cursor + 100 > len(blob):
                raise ValueError(
                    f"selector record {index} overruns blob: need {cursor + 100:#x}, have {len(blob):#x}"
                )
            entry = blob[cursor:cursor + 100]
            if entry[99] != 0:
                raise ValueError(f"selector record {index} path is not NUL-terminated")
            selector_key = struct.unpack_from("<I", entry, 0)[0]
            opaque_prefix = entry[4:36]
            tail_name = decode_c_string(entry[36:])
            note = ""
            if not tail_name:
                note = " [empty filename; prefix32 kept opaque]"
            print(
                f"[{index}] selector_key={selector_key:#x} "
                f"prefix32={opaque_prefix.hex()} filename={tail_name!r}{note}"
            )
            cursor += 100
        if cursor != len(blob):
            print(f"trailing_bytes={len(blob) - cursor}")
        return 0

    if magic == 0xDEADD00F:
        if len(blob) < 0x18:
            raise ValueError("DEADD00F record too small")
        raw_flags_04 = struct.unpack_from("<I", blob, 4)[0]
        enabled = blob[5] != 0
        ttl_seconds = struct.unpack_from("<I", blob, 8)[0]
        print(f"kind=deadd00f magic={magic:#x} raw_flags_04={raw_flags_04:#x}")
        print(f"enabled={enabled}")
        print(f"ttl_seconds={ttl_seconds:#x}")

        if len(blob) >= 0x10:
            print(f"field_0c={struct.unpack_from('<I', blob, 0x0c)[0]:#x}")
        if len(blob) >= 0x14:
            print(f"field_10={struct.unpack_from('<I', blob, 0x10)[0]:#x}")
        if len(blob) >= 0x18:
            print(f"field_14={struct.unpack_from('<I', blob, 0x14)[0]:#x}")
        if len(blob) >= 0x1c:
            print(f"field_18={struct.unpack_from('<I', blob, 0x18)[0]:#x}")

        if len(blob) >= 0x24:
            string_offset = struct.unpack_from("<I", blob, 0x1c)[0]
            string_length = struct.unpack_from("<I", blob, 0x20)[0]
            if string_offset + string_length > len(blob):
                raise ValueError(
                    f"string overruns blob: offset={string_offset:#x} length={string_length:#x} size={len(blob):#x}"
                )
            payload_name = decode_c_string(blob[string_offset:string_offset + string_length])
            print(f"string_offset={string_offset:#x}")
            print(f"string_length={string_length:#x}")
            print(f"payload_name={payload_name!r}")
            trailing = len(blob) - (string_offset + string_length)
            if trailing:
                print(f"trailing_bytes={trailing}")
        return 0

    if magic == 0xF00DBEEF:
        if len(blob) < 8:
            raise ValueError("container too small")
        count = struct.unpack_from("<I", blob, 4)[0]
        print(f"kind=container magic={magic:#x} count={count}")
        for index in range(count):
            table_off = 8 + index * 16
            if table_off + 16 > len(blob):
                raise ValueError(f"entry table truncated at index {index}")
            f1, f2, data_offset, size = struct.unpack_from("<IIII", blob, table_off)
            print(
                f"[{index}] f1={f1:#x} f2={f2:#x} "
                f"data_offset={data_offset:#x} size={size:#x}"
            )
        return 0

    raise ValueError(f"unknown record magic: {magic:#x}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline helpers for Coruna payload reconstruction."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_sections = subparsers.add_parser("list-sections", help="list Mach-O sections")
    list_sections.add_argument("macho", help="path to a Mach-O or universal binary")
    list_sections.add_argument("--arch", help="slice name for universal binaries, e.g. arm64e")
    list_sections.set_defaults(func=cmd_list_sections)

    extract = subparsers.add_parser("extract-section", help="extract one Mach-O section")
    extract.add_argument("macho", help="path to a Mach-O or universal binary")
    extract.add_argument("--segment", required=True, help="segment name, e.g. __TEXT")
    extract.add_argument("--section", required=True, help="section name, e.g. __SBTweak")
    extract.add_argument("--output", required=True, help="path for extracted bytes")
    extract.add_argument("--arch", help="slice name for universal binaries, e.g. arm64e")
    extract.set_defaults(func=cmd_extract_section)

    build = subparsers.add_parser(
        "build-container",
        help="rebuild the Stage3 output blob (F00DBEEF container or raw passthrough)",
    )
    build.add_argument("--manifest", required=True, help="path to payloads/manifest.json")
    build.add_argument("--payload-root", required=True, help="path to payloads directory")
    build.add_argument("--hash-name", required=True, help="hash directory from manifest")
    build.add_argument("--output", required=True, help="output container path")
    build.add_argument(
        "--emulate-live-stage3",
        action="store_true",
        help="rewrite entry2_type0x0f.dylib to the local TweakLoader, matching Stage3_VariantB.js",
    )
    build.add_argument(
        "--has-pac",
        action="store_true",
        help="when emulating live Stage3, use arm64e TweakLoader instead of arm64",
    )
    build.add_argument(
        "--tweakloader-root",
        help="override the TweakLoader obj root; default matches the original unpublished workspace layout relative to payload-root",
    )
    build.add_argument(
        "--strict-manifest-sizes",
        action="store_true",
        help="treat manifest size mismatches as fatal instead of using the fetched byte length",
    )
    build.set_defaults(func=cmd_build_container)

    inspect_record = subparsers.add_parser(
        "inspect-record",
        help="inspect selector, DEADD00F, or F00DBEEF blobs",
    )
    inspect_record.add_argument("path", help="path to a record blob or reconstructed container")
    inspect_record.set_defaults(func=cmd_inspect_record)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
