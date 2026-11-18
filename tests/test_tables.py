from arm_soc_sbsa.tables.acpi import build_all, build_madt, parse_table, validate_blob, checksum_ok
from arm_soc_sbsa.tables.smbios import build_smbios, parse_smbios


def test_all_tables_roundtrip_and_checksum():
    for name, blob in build_all().items():
        assert checksum_ok(blob), name
        info = parse_table(blob)
        assert info["signature"] == name
        assert info["length"] == len(blob) and info["length_ok"]
        assert validate_blob(blob) == []


def test_madt_cpu_count():
    assert parse_table(build_madt(num_cpus=4))["num_cpus"] == 4
    assert parse_table(build_madt(num_cpus=2))["num_cpus"] == 2


def test_corrupt_checksum_detected():
    blob = bytearray(build_madt())
    blob[20] ^= 0xFF
    assert not checksum_ok(bytes(blob))
    assert validate_blob(bytes(blob))


def test_smbios_roundtrip():
    structs = parse_smbios(build_smbios(num_cpus=4))
    types = [s["type"] for s in structs]
    assert 0 in types and 1 in types and types.count(4) == 4 and types[-1] == 127
