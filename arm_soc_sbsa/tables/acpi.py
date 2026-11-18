"""Custom ACPI table generation: MADT, GTDT, IORT, PPTT (+ RSDP/XSDT helpers).

Tables are emitted as binary .dat blobs with correct lengths and ACPI
checksums (sum of all bytes == 0 mod 256), then parsed back by `parse_table`
for round-trip validation. This is a teaching/pre-silicon model of the real
structures (ACPI 6.5), not a replacement for iASL/EDK II table production.
AML generation is intentionally out of scope.
"""
from __future__ import annotations

import struct

HEADER_LEN = 36
OEMID = b"ARMLTD"
CREATOR_ID = b"PYAC"


def _header(sig: bytes, length: int, revision: int, oem_table_id: bytes) -> bytearray:
    assert len(sig) == 4
    h = bytearray()
    h += sig
    h += struct.pack("<I", length)
    h += struct.pack("<B", revision)
    h += struct.pack("<B", 0)  # checksum placeholder
    h += OEMID.ljust(6, b" ")
    h += oem_table_id.ljust(8, b" ")[:8]
    h += struct.pack("<I", 1)  # OEM revision
    h += CREATOR_ID
    h += struct.pack("<I", 1)  # creator revision
    assert len(h) == HEADER_LEN
    return h


def _finalize(buf: bytearray) -> bytes:
    buf[9] = (-sum(buf)) & 0xFF
    return bytes(buf)


def checksum_ok(blob: bytes) -> bool:
    return len(blob) > 0 and (sum(blob) & 0xFF) == 0


# ---------------- MADT ----------------
def build_madt(num_cpus: int = 4, gicd_base: int = 0x40060000, gicc_base: int = 0x40080000, its_base: int = 0x40064000) -> bytes:
    entries = bytearray()
    for i in range(num_cpus):
        # GICC (type 11, len 80) ACPI 6.5 Table 5-60 (simplified fields)
        e = bytearray(80)
        e[0] = 11
        e[1] = 80
        struct.pack_into("<H", e, 2, 0)          # reserved
        struct.pack_into("<I", e, 4, i)          # ACPI processor UID
        struct.pack_into("<I", e, 8, i)          # MPIDR low
        struct.pack_into("<I", e, 12, 1)         # flags: enabled
        struct.pack_into("<Q", e, 24, gicc_base + i * 0x20000)  # GICR base (model)
        struct.pack_into("<Q", e, 56, 27)         # VGIC maintenance GSIV placeholder area reuse
        entries += e
    # GICD (type 12, len 24)
    gicd = bytearray(24)
    gicd[0] = 12
    gicd[1] = 24
    struct.pack_into("<I", gicd, 4, 0)
    struct.pack_into("<Q", gicd, 8, gicd_base)
    gicd[20] = 3  # GIC version 3
    entries += gicd
    # GIC ITS (type 21 / 0x15, len 20) — ACPI uses 21 for ITS in newer specs; keep explicit
    its = bytearray(20)
    its[0] = 21
    its[1] = 20
    struct.pack_into("<I", its, 4, 0)
    struct.pack_into("<Q", its, 8, its_base)
    entries += its

    body_len = 8 + len(entries)  # LocalIntcAddr(4)+Flags(4)
    buf = _header(b"MADT", HEADER_LEN + body_len, 5, b"SBSAREF ")
    buf += struct.pack("<II", 0, 1)  # local intc addr (legacy), flags PCAT_COMPAT
    buf += entries
    return _finalize(buf)


# ---------------- GTDT ----------------
def build_gtdt(cntfrq_hz: int = 100_000_000) -> bytes:
    # GTDT body after header: CounterBlock(8) Reserved(4) SecurePL1(4+4+4) NonSecurePL1(...)
    # Simplified fixed 104-byte total table.
    total = 104
    buf = _header(b"GTDT", total, 2, b"SBSAREF ")
    buf += struct.pack("<QI", 0xFFFFFFFFFFFFFFFF, 0)  # cnt block, reserved
    buf += struct.pack("<III", 29, 0x4, 0)            # Secure PL1 GSIV, flags, virtual offset? packed model
    buf += struct.pack("<III", 30, 0x4, 0)            # Non-secure PL1
    buf += struct.pack("<III", 27, 0x4, 0)            # Virtual timer
    buf += struct.pack("<III", 26, 0x4, 0)            # Hypervisor timer
    buf += struct.pack("<Q", 0)                       # CntReadBase
    buf += struct.pack("<I", 1)                       # PlatformTimerCount
    buf += struct.pack("<I", HEADER_LEN + 68)         # PlatformTimerOffset
    # Pad / watchdog timer entry (GT Block / watchdog simplified 24 bytes may exceed; trim/pad to total)
    if len(buf) < total:
        buf += bytes(total - len(buf))
    else:
        buf = buf[:total]
        struct.pack_into("<I", buf, 4, total)
    # Store CNTFRQ in reserved area of header-adjacent field for round-trip (creator rev area untouched)
    # Encode in PlatformTimerCount-adjacent padding: use bytes 92..96
    struct.pack_into("<I", buf, 92, cntfrq_hz // 1_000_000)  # MHz, checked by parser/tests
    return _finalize(buf)


# ---------------- IORT ----------------
def build_iort() -> bytes:
    # Header + NumNodes(4)+Offset(4)+Reserved(4) + one ITS Group node
    node_len = 24  # type(1)+len(2)+rev(1)+reserved(4)+mappings(4)+its_count(4)+identifiers(4*2?) simplified
    total = HEADER_LEN + 12 + node_len
    buf = _header(b"IORT", total, 3, b"SBSAREF ")
    buf += struct.pack("<III", 1, HEADER_LEN + 12, 0)
    node = bytearray(node_len)
    node[0] = 0  # ITS Group = 0
    struct.pack_into("<H", node, 1, node_len)
    node[3] = 1  # revision
    struct.pack_into("<I", node, 8, 0)   # number of ID mappings
    struct.pack_into("<I", node, 12, 1)  # number of ITS identifiers
    struct.pack_into("<I", node, 16, 0)  # ITS id 0
    struct.pack_into("<I", node, 20, 1)  # flags / second word marker for SMMU presence in tests (model)
    buf += node
    return _finalize(buf)


# ---------------- PPTT ----------------
def build_pptt(num_cpus: int = 4) -> bytes:
    # Processor Hierarchy Nodes (type 0, len 20 each in ACPI 6.5; we use 24 with ACPI UID)
    nodes = bytearray()
    nodes += _pptt_node(flags=0x1, parent=0, acpi_uid=0xFFFFFFFF)  # package/cluster root (invalid UID = physical package)
    cluster_offset = HEADER_LEN  # offset of first node from table start
    for i in range(num_cpus):
        nodes += _pptt_node(flags=0x2 | 0x4 | 0x8, parent=cluster_offset, acpi_uid=i)
    total = HEADER_LEN + len(nodes)
    buf = _header(b"PPTT", total, 2, b"SBSAREF ")
    buf += nodes
    return _finalize(buf)


def _pptt_node(flags: int, parent: int, acpi_uid: int) -> bytes:
    n = bytearray(24)
    n[0] = 0
    n[1] = 24
    struct.pack_into("<I", n, 4, flags)
    struct.pack_into("<I", n, 8, parent)
    struct.pack_into("<I", n, 12, acpi_uid)
    struct.pack_into("<I", n, 16, 0)  # number of private resources
    return bytes(n)


TABLE_BUILDERS = {"MADT": build_madt, "GTDT": build_gtdt, "IORT": build_iort, "PPTT": build_pptt}


def build_all(num_cpus: int = 4) -> dict[str, bytes]:
    return {name: fn(num_cpus=num_cpus) if name in ("MADT", "PPTT") else fn() for name, fn in TABLE_BUILDERS.items()}


def parse_table(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ValueError("table too short for ACPI header")
    sig = blob[0:4].decode("ascii", errors="strict")
    length, revision, checksum = struct.unpack_from("<IBB", blob, 4)
    oemid = blob[10:16].decode("ascii", errors="replace").strip()
    info: dict = {
        "signature": sig, "length": length, "revision": revision,
        "checksum": checksum, "oem_id": oemid,
        "checksum_ok": checksum_ok(blob), "length_ok": length == len(blob),
    }
    if sig == "MADT":
        gicc = gicd = its = 0
        off = HEADER_LEN + 8
        while off + 2 <= len(blob):
            t, ln = blob[off], blob[off + 1]
            if ln == 0:
                break
            if t == 11:
                gicc += 1
            elif t == 12:
                gicd += 1
            elif t == 21:
                its += 1
            off += ln
        info.update({"gicc_count": gicc, "gicd_count": gicd, "its_count": its, "num_cpus": gicc})
    elif sig == "GTDT":
        info.update({"cntfrq_mhz": struct.unpack_from("<I", blob, 92)[0] if len(blob) >= 96 else 0})
    elif sig == "IORT":
        num_nodes, offset = struct.unpack_from("<II", blob, HEADER_LEN)
        info.update({"num_nodes": num_nodes, "first_node_offset": offset,
                     "its_group_present": len(blob) > offset and blob[offset] == 0})
    elif sig == "PPTT":
        count = 0
        cpus = 0
        off = HEADER_LEN
        while off + 24 <= len(blob):
            ln = blob[off + 1]
            if ln == 0:
                break
            uid = struct.unpack_from("<I", blob, off + 12)[0]
            count += 1
            if uid != 0xFFFFFFFF:
                cpus += 1
            off += ln
        info.update({"node_count": count, "num_cpus": cpus})
    return info


def validate_blob(blob: bytes) -> list[str]:
    """Return list of errors (empty = valid)."""
    errors: list[str] = []
    try:
        info = parse_table(blob)
    except Exception as e:  # noqa: BLE001
        return [str(e)]
    if not info["checksum_ok"]:
        errors.append(f"{info['signature']}: bad checksum")
    if not info["length_ok"]:
        errors.append(f"{info['signature']}: length field {info['length']} != blob {len(blob)}")
    if info["signature"] == "MADT" and info.get("gicc_count", 0) == 0:
        errors.append("MADT: no GICC entries")
    if info["signature"] == "MADT" and info.get("gicd_count", 0) != 1:
        errors.append("MADT: expected exactly one GICD")
    if info["signature"] == "IORT" and info.get("num_nodes", 0) < 1:
        errors.append("IORT: no nodes")
    if info["signature"] == "PPTT" and info.get("num_cpus", 0) == 0:
        errors.append("PPTT: no CPU nodes")
    return errors
