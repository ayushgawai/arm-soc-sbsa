"""Minimal SMBIOS structure generation + parsing (teaching model).

Emits Type 0 (BIOS), Type 1 (System), Type 4 (Processor, one per CPU) and
Type 127 (End-of-Table) structures with string sets, terminated per SMBIOS
convention (double-null). Not a full SMBIOS 3.x implementation.
"""
from __future__ import annotations

import struct


def _struct(type_: int, formatted: bytes, strings: list[str]) -> bytes:
    length = 4 + len(formatted)
    handle = _struct.counter  # type: ignore[attr-defined]
    _struct.counter += 1  # type: ignore[attr-defined]
    out = bytearray(struct.pack("<BBH", type_, length, handle))
    out += formatted
    for s in strings:
        out += s.encode() + b"\x00"
    out += b"\x00"
    return bytes(out)


_struct.counter = 0  # type: ignore[attr-defined]


def build_smbios(num_cpus: int = 4, version: str = "0.1.0") -> bytes:
    _struct.counter = 0  # type: ignore[attr-defined]
    blob = bytearray()
    # Type 0: vendor, version, release date string indices
    blob += _struct(0, bytes([1, 2, 0, 0, 3]) + bytes(11), ["arm-soc-sbsa", version, "01/01/2026"])
    # Type 1: manufacturer, product, version, serial
    blob += _struct(1, bytes([1, 2, 3, 4]) + bytes(16), ["SBSA Lab", "sbsa-ref mock", "1.0", "MOCK-0001"])
    for i in range(num_cpus):
        blob += _struct(4, bytes([1, 2, 3]) + bytes([0xFE]) + bytes(20), [f"CPU{i} socket", "Arm Neoverse (model)", "Mock CPU"])
    blob += _struct(127, b"", [])
    return bytes(blob)


def parse_smbios(blob: bytes) -> list[dict]:
    out: list[dict] = []
    off = 0
    while off + 4 <= len(blob):
        type_, length, handle = struct.unpack_from("<BBH", blob, off)
        if length < 4:
            break
        # string set starts at off+length, ends at double-null
        end = off + length
        strings: list[str] = []
        cur = bytearray()
        # scan until \0\0
        i = end
        while i < len(blob):
            if blob[i] == 0:
                if cur:
                    strings.append(cur.decode(errors="replace"))
                    cur = bytearray()
                if i + 1 < len(blob) and blob[i + 1] == 0:
                    i += 2
                    break
                i += 1
            else:
                cur.append(blob[i])
                i += 1
        out.append({"type": type_, "length": length, "handle": handle, "strings": strings})
        if type_ == 127:
            break
        off = i
    return out
