#!/usr/bin/env python3
"""
regmsgd anti-tamper disabler

Patches the anti-tamper marker in regmsgd binaries to the unpatched
placeholder value (0xA5 x 32), which makes the self-hash code skip the
anti-tamper system entirely (fail-open path).  This restores the ability to:

  - Modify the binary (debugging, hotfixes)
  - Attach a debugger (strace, gdb) without breaking launches
  - Customise the boot splash or init script
  - Fork or rebrand REG-Linux

The marker sits between a 128-byte sealed credential blob and a 32-byte
launch seal.  Only the 32-byte marker is changed; the rest of the binary
is untouched.

Works on both x86_64 and aarch64 ELF binaries.

Usage:
  python3 disable_antitamper.py regmsgd
  python3 disable_antitamper.py regmsgd -o regmsgd.patched
  python3 disable_antitamper.py regmsgd --offset 0xa370e0   # manual
"""

import argparse
import math
import os
import struct
import sys
from pathlib import Path

MARKER_SIZE = 32
SEALED_SIZE = 128
SEAL_SIZE = 32
REGION_SIZE = SEALED_SIZE + MARKER_SIZE + SEAL_SIZE  # 192
PLACEHOLDER = b"\xa5" * MARKER_SIZE


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n) for c in counts if c
    )


def elf_arch(data: bytes) -> str:
    """Return 'x86_64', 'aarch64', or 'unknown'."""
    if data[:4] != b"\x7fELF":
        return "not_elf"
    machine = struct.unpack_from("<H", data, 18)[0]
    return {0x3E: "x86_64", 0xB7: "aarch64"}.get(machine, f"unknown(0x{machine:x})")


def looks_like_slots(data: bytes, region_start: int) -> bool:
    """Heuristic: sealed blob and launch seal should have high entropy."""
    sealed = data[region_start : region_start + SEALED_SIZE]
    seal_start = region_start + SEALED_SIZE + MARKER_SIZE
    seal = data[seal_start : seal_start + SEAL_SIZE]
    return entropy(sealed) > 4.5 and entropy(seal) > 4.0


# ---------------------------------------------------------------------------
# search strategies
# ---------------------------------------------------------------------------

def find_by_boundary_strings(data: bytes):
    """
    Strategy 1: unique concatenated Rust string constants that flank the
    patch region.  Verified on the da5cd551 x86_64 build.
    """
    # Known boundary pairs (add more if future builds rearrange strings)
    pairs = [
        (b"PortVirtualDSIDPIWritebackSPIUSB",
         b"systemsbiosFilestransformfocused"),
    ]
    for before, after in pairs:
        bi = data.find(before)
        ai = data.find(after)
        if bi < 0 or ai < 0:
            continue
        region_start = bi + len(before)
        expected_end = region_start + REGION_SIZE
        if ai != expected_end:
            continue
        if looks_like_slots(data, region_start):
            marker_off = region_start + SEALED_SIZE
            return marker_off, (
                f"boundary strings at 0x{bi:x}..0x{ai:x}"
            )
    return None, None


def find_by_entropy_scan(data: bytes):
    """
    Strategy 2: scan the binary for a 192-byte window of high entropy
    (>6.0 bits/byte) bordered on both sides by >=16 bytes of lower entropy
    (<5.0).  The patch region stands out because it is random-looking data
    embedded in string / relocation tables.
    """
    WINDOW = REGION_SIZE
    BORDER = 16
    candidates = []

    # Slide a coarse window
    step = 16
    for off in range(BORDER, len(data) - WINDOW - BORDER, step):
        region = data[off : off + WINDOW]
        if entropy(region) < 6.0:
            continue
        pre = data[off - BORDER : off]
        post = data[off + WINDOW : off + WINDOW + BORDER]
        if entropy(pre) > 5.0 or entropy(post) > 5.0:
            continue
        # Refine: check the three sub-regions
        if looks_like_slots(data, off):
            marker_off = off + SEALED_SIZE
            candidates.append(marker_off)

    if len(candidates) == 1:
        return candidates[0], "entropy scan (unique high-entropy region)"
    if len(candidates) > 1:
        return None, f"entropy scan found {len(candidates)} candidates — use --offset"
    return None, None


def find_by_context_strings(data: bytes):
    """
    Strategy 3: the BLAKE3 derive_key contexts 'regmsg-launch-v1' and
    'regmsg-cred-v1' are stored as plaintext.  They live in the same
    segment as the patch slots.  Use them to narrow the entropy scan.
    """
    launch_ctx = b"regmsg-launch-v1"
    cred_ctx = b"regmsg-cred-v1"
    li = data.find(launch_ctx)
    ci = data.find(cred_ctx)
    if li < 0 and ci < 0:
        return None, None

    # The slots are between the two context strings (roughly)
    lo = min(x for x in [li, ci] if x >= 0)
    hi = max(x for x in [li, ci] if x >= 0) + 32

    # Widen the search window a bit
    search_lo = max(0, lo - 0x100000)
    search_hi = min(len(data), hi + 0x100000)

    step = 16
    candidates = []
    for off in range(search_lo, search_hi - REGION_SIZE, step):
        region = data[off : off + REGION_SIZE]
        if entropy(region) < 6.0:
            continue
        if looks_like_slots(data, off):
            marker_off = off + SEALED_SIZE
            candidates.append(marker_off)

    if len(candidates) == 1:
        return candidates[0], (
            f"context strings + entropy (near 0x{lo:x})"
        )
    return None, None


# ---------------------------------------------------------------------------
# main search
# ---------------------------------------------------------------------------

def find_marker(data: bytes):
    """Try each strategy in order.  Return (offset, method) or (None, reason)."""

    # Check if already disabled
    for off in range(0, len(data) - REGION_SIZE):
        idx = data.find(PLACEHOLDER, off)
        if idx < 0:
            break
        # Verify context
        region_start = idx - SEALED_SIZE
        if region_start >= 0 and looks_like_slots(data, region_start):
            return idx, "already_disabled"
        off = idx + 1

    # Strategy 1
    offset, method = find_by_boundary_strings(data)
    if offset is not None:
        return offset, method

    # Strategy 2
    offset, method = find_by_entropy_scan(data)
    if offset is not None:
        return offset, method

    # Strategy 3
    offset, method = find_by_context_strings(data)
    if offset is not None:
        return offset, method

    return None, "could not locate the anti-tamper marker"


# ---------------------------------------------------------------------------
# patch
# ---------------------------------------------------------------------------

def patch_binary(in_path: str, out_path: str, manual_offset: int = None):
    data = bytearray(Path(in_path).read_bytes())
    arch = elf_arch(data)

    print(f"Binary:       {in_path}")
    print(f"Size:         {len(data):,} bytes")
    print(f"Architecture: {arch}")
    if arch == "not_elf":
        print("Error: not an ELF binary.", file=sys.stderr)
        return False
    print()

    if manual_offset is not None:
        marker_off = manual_offset
        method = "manual offset"
        # Verify it looks right
        region_start = marker_off - SEALED_SIZE
        if region_start < 0 or marker_off + MARKER_SIZE > len(data):
            print(f"Error: offset 0x{marker_off:x} is out of range.", file=sys.stderr)
            return False
        if not looks_like_slots(data, region_start):
            print(f"Warning: the region around 0x{marker_off:x} does not look "
                  f"like the expected patch slots (low entropy).", file=sys.stderr)
            print(f"Proceeding anyway since --offset was given explicitly.\n")
    else:
        marker_off, method = find_marker(data)
        if marker_off is None:
            print(f"Error: {method}", file=sys.stderr)
            print("Use --offset to specify the marker offset manually.",
                  file=sys.stderr)
            return False

    if method == "already_disabled":
        print(f"Marker at 0x{marker_off:x} is already all-0xA5.")
        print("The anti-tamper system is already disabled. Nothing to do.")
        return True

    print(f"Found marker: 0x{marker_off:x}  ({method})")
    marker = bytes(data[marker_off : marker_off + MARKER_SIZE])
    print(f"Current value: {marker.hex()}")
    print(f"Patch value:   {'a5' * MARKER_SIZE}")
    print()

    # Show what's around it for verification
    sealed = bytes(data[marker_off - SEALED_SIZE : marker_off])
    seal = bytes(data[marker_off + MARKER_SIZE : marker_off + MARKER_SIZE + SEAL_SIZE])
    print(f"Sealed blob ({SEALED_SIZE}B) entropy: {entropy(sealed):.2f} bits/byte")
    print(f"Launch seal  ({SEAL_SIZE}B) entropy: {entropy(seal):.2f} bits/byte")
    print()

    # Patch
    data[marker_off : marker_off + MARKER_SIZE] = PLACEHOLDER

    # Write
    Path(out_path).write_bytes(data)
    os.chmod(out_path, 0o755)

    print(f"Patched:      {out_path}")
    print(f"Changed:      32 bytes at 0x{marker_off:x} -> 0xA5 x 32")
    print()
    print("The anti-tamper system is now disabled.  The daemon will:")
    print("  - Launch emulators regardless of binary/splash modifications")
    print("  - Work normally under strace / gdb")
    print("  - Ignore changes to the init script or plymouth splash")
    print()
    print("Note: the sealed ScreenScraper developer credentials will no")
    print("longer unseal (they depend on the same key material).  User-")
    print("configured scraper credentials are unaffected.")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Disable the anti-tamper system in regmsgd binaries."
    )
    parser.add_argument("binary", help="Path to the regmsgd binary")
    parser.add_argument(
        "-o", "--output",
        help="Output path (default: overwrite in place)",
    )
    parser.add_argument(
        "--offset",
        type=lambda x: int(x, 0),
        help="Manual marker offset (hex or decimal), e.g. 0xa370e0",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Find and report the marker but don't patch",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"Error: {args.binary} not found.", file=sys.stderr)
        sys.exit(1)

    out_path = args.output or args.binary

    if args.dry_run:
        data = Path(args.binary).read_bytes()
        arch = elf_arch(data)
        print(f"Binary:       {args.binary}")
        print(f"Architecture: {arch}")
        if args.offset is not None:
            print(f"Manual offset: 0x{args.offset:x}")
            marker = data[args.offset : args.offset + MARKER_SIZE]
            is_disabled = marker == PLACEHOLDER
            print(f"Marker value: {marker.hex()}")
            print(f"Disabled:     {is_disabled}")
        else:
            offset, method = find_marker(data)
            if offset is None:
                print(f"Result:       {method}")
            elif method == "already_disabled":
                print(f"Marker at:    0x{offset:x}")
                print(f"Status:       already disabled")
            else:
                print(f"Marker at:    0x{offset:x}")
                print(f"Method:       {method}")
                print(f"Value:        {data[offset:offset+MARKER_SIZE].hex()}")
        sys.exit(0)

    success = patch_binary(args.binary, out_path, args.offset)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
