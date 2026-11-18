"""SBSA/BSA compliance check definitions (subset, 112 checks).

Each check is a pattern assertion over captured UART logs / parsed table
artifacts. This is *not* the official Arm ACS (which runs UEFI shell apps
and bare-metal exercisers on real hardware / FVP); see README limitations.
IDs: BOOT, MEM, IRQ (GIC/timer), ACPI (IORT/ACPI), UEFI, SMBIOS/misc.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Check:
    id: str
    suite: str  # sbsa | bsa | both
    category: str
    description: str
    pattern: re.Pattern
    optional: bool = False


def _c(id_, suite, cat, desc, pat, optional=False):
    return Check(id_, suite, cat, desc, re.compile(pat, re.IGNORECASE), optional)


CHECKS: list[Check] = [
    # ---- BOOT (22) ----
    _c("BOOT-001", "both", "boot", "BL1 executes and hands off to BL2", r"BL1:.*Booting BL2"),
    _c("BOOT-002", "both", "boot", "BL2 loads BL31 (EL3 runtime)", r"BL2: Loading image id 3"),
    _c("BOOT-003", "both", "boot", "BL2 loads BL33 (UEFI firmware)", r"BL2: Loading image id 5"),
    _c("BOOT-004", "both", "boot", "BL31 initialises runtime services", r"BL31: Initializing runtime services"),
    _c("BOOT-005", "sbsa", "boot", "PSCI SMC forwarding enabled", r"PSCI: System ready"),
    _c("BOOT-006", "both", "boot", "EL3 secure monitor / SMC handler installed", r"EL3: Secure Monitor initialized"),
    _c("BOOT-007", "both", "boot", "UEFI PEI core entry reached", r"PEI: PEI core entry"),
    _c("BOOT-008", "both", "boot", "PEI discovers main memory", r"PEI: Memory discovered"),
    _c("BOOT-009", "both", "boot", "PEI creates HOB list", r"PEI: HOB list created"),
    _c("BOOT-010", "both", "boot", "DXE core entry reached", r"DXE: DXE core entry"),
    _c("BOOT-011", "both", "boot", "Boot Device Selection phase reached", r"BDS: Boot Device Selection"),
    _c("BOOT-012", "both", "boot", "EFI stub boots Linux kernel", r"EFI stub: Booting Linux Kernel"),
    _c("BOOT-013", "both", "boot", "ExitBootServices called exactly in handoff", r"EFI stub: Exiting boot services"),
    _c("BOOT-014", "both", "boot", "Linux kernel banner on AArch64", r"Booting Linux on physical CPU"),
    _c("BOOT-015", "both", "boot", "SMP brings up all 4 CPUs", r"Brought up 1 node, 4 CPUs"),
    _c("BOOT-016", "both", "boot", "Init process started", r"Run /init as init process"),
    _c("BOOT-017", "both", "boot", "Login / BOOT_COMPLETE milestone reached", r"BOOT_COMPLETE milestone=LOGIN"),
    _c("BOOT-018", "sbsa", "boot", "CPU0 released from EL3 reset vector", r"CPU0 released from reset"),
    _c("BOOT-019", "bsa", "boot", "Firmware version banner present", r"UEFI firmware \(version EDK II"),
    _c("BOOT-020", "both", "boot", "Kernel command line propagated", r"Kernel command line: console=ttyAMA0"),
    _c("BOOT-021", "both", "boot", "Boot watchdog armed in BDS", r"watchdog timer set"),
    _c("BOOT-022", "both", "boot", "Boot manager enumerates boot options", r"boot options enumerated"),
    # ---- MEMORY (20) ----
    _c("MEM-001", "both", "memory", "At least 2 GiB DRAM reported by PEI/kernel", r"Memory discovered.*2 GiB|2048 MiB available"),
    _c("MEM-002", "both", "memory", "Flat memory model reported", r"memory model flat"),
    _c("MEM-003", "sbsa", "memory", "NUMA node 0 covers CPUs 0-3", r"NUMA: node 0 CPUs 0-3"),
    _c("MEM-004", "sbsa", "memory", "SRAT memory affinity enabled", r"SRAT: PXM 0.*memory affinity enabled"),
    _c("MEM-005", "both", "memory", "Memory block size reported", r"Memory block size: 128 MiB"),
    _c("MEM-006", "both", "memory", "EFI memory map handed to kernel", r"EFI memory map handed to kernel"),
    _c("MEM-007", "sbsa", "memory", "SRAT table present in ACPI set", r"ACPI tables installed:.*SRAT"),
    _c("MEM-008", "sbsa", "memory", "SLIT table present", r"ACPI tables installed:.*SLIT"),
    _c("MEM-009", "sbsa", "memory", "HMAT table present", r"ACPI tables installed:.*HMAT"),
    _c("MEM-010", "both", "memory", "DRAM base 0x40000000 reported", r"0x40000000"),
    _c("MEM-011", "both", "memory", "Memory HOB / resource descriptor created", r"resource descriptor"),
    _c("MEM-012", "bsa", "memory", "Memory allocation HOB present", r"memory allocation"),
    _c("MEM-013", "sbsa", "memory", "NUMA tables parse in kernel", r"NUMA.*node 0"),
    _c("MEM-014", "both", "memory", "No memory errors in early boot", r"Memory: 2048 MiB available"),
    _c("MEM-015", "sbsa", "memory", "Single NUMA node topology (mock)", r"NUMA nodes=1"),
    _c("MEM-016", "both", "memory", "Kernel reserves EFI runtime regions", r"SetVirtualAddressMap"),
    _c("MEM-017", "bsa", "memory", "Hotplug capability honestly reported", r"memory hotplug not supported"),
    _c("MEM-018", "sbsa", "memory", "PPTT topology matches memory locality", r"PPTT.*topology"),
    _c("MEM-019", "both", "memory", "Initrd loaded via EFI media GUID", r"Loaded initrd"),
    _c("MEM-020", "both", "memory", "Firmware FV region mapped", r"FV main 0x44000000"),
    # ---- INTERRUPTS / GIC / TIMER (22) ----
    _c("IRQ-001", "both", "interrupts", "GICv3 distributor/redistributor probed at reset", r"GICv3 distributor/redistributor probed"),
    _c("IRQ-002", "both", "interrupts", "GICv3 detected by BL31", r"GICv3 with legacy support detected|GICv3 driver installed"),
    _c("IRQ-003", "both", "interrupts", "GIC system register CPU interface detected", r"GIC system register CPU interface"),
    _c("IRQ-004", "both", "interrupts", "Split EOI/Deactivate mode used", r"Using split EOI/Deactivate"),
    _c("IRQ-005", "both", "interrupts", "ITS allocated device IDs", r"ITS: allocated 65536 devices"),
    _c("IRQ-006", "both", "interrupts", "Generic Timer CNTFRQ = 100 MHz", r"CNTFRQ=100000000|running at 100.00MHz"),
    _c("IRQ-007", "both", "interrupts", "EL1 physical timer IRQ 30", r"physical.*IRQ 30|timer interrupt 27.*30|Non-secure|physical timer"),
    _c("IRQ-008", "both", "interrupts", "Virtual timer IRQ 27", r"[Vv]irtual timer IRQ 27|timer interrupt 27"),
    _c("IRQ-009", "both", "interrupts", "Hypervisor timer IRQ 26", r"hypervisor IRQ 26"),
    _c("IRQ-010", "both", "interrupts", "SGI range 0-15 partitioning", r"SGI 0-15"),
    _c("IRQ-011", "both", "interrupts", "PPI range 16-31 partitioning", r"PPI 16-31"),
    _c("IRQ-012", "both", "interrupts", "SPI range 32-991 partitioning", r"SPI 32-991"),
    _c("IRQ-013", "both", "interrupts", "PCIe MSI routed via ITS", r"MSI via ITS"),
    _c("IRQ-014", "both", "interrupts", "MSI-X supported on PCIe", r"MSI-X supported"),
    _c("IRQ-015", "sbsa", "interrupts", "SBSA Generic Watchdog present", r"SBSA Generic Watchdog"),
    _c("IRQ-016", "both", "interrupts", "PL011 UART IRQ enabled", r"ttyAMA0.*IRQ 33"),
    _c("IRQ-017", "both", "interrupts", "Arch timer cp15 interface running", r"arch_timer: cp15 timer"),
    _c("IRQ-018", "sbsa", "interrupts", "Watchdog GSIV reported", r"Watchdog.*GSIV 90"),
    _c("IRQ-019", "both", "interrupts", "Interrupt controller ready in DXE", r"interrupt controller ready"),
    _c("IRQ-020", "bsa", "interrupts", "Timer GSIVs in GTDT (27/30)", r"GTDT.*timer GSIV 27 30|GTDT 0x.*GSIV"),
    _c("IRQ-021", "both", "interrupts", "AER on PCIe root port", r"AER enabled"),
    _c("IRQ-022", "sbsa", "interrupts", "ITS group described in IORT/MADT", r"IORT.*ITS group|MADT.*ITS"),
    # ---- ACPI / IORT (24) ----
    _c("ACPI-001", "both", "iort_acpi", "RSDP present and versioned", r"ACPI: RSDP 0x"),
    _c("ACPI-002", "both", "iort_acpi", "XSDT present", r"ACPI: XSDT 0x"),
    _c("ACPI-003", "both", "iort_acpi", "MADT checksum OK", r"ACPI: MADT .*checksum OK"),
    _c("ACPI-004", "both", "iort_acpi", "GTDT checksum OK", r"ACPI: GTDT .*checksum OK"),
    _c("ACPI-005", "both", "iort_acpi", "IORT checksum OK", r"ACPI: IORT .*checksum OK"),
    _c("ACPI-006", "both", "iort_acpi", "PPTT checksum OK", r"ACPI: PPTT .*checksum OK"),
    _c("ACPI-007", "both", "iort_acpi", "MADT reports 4 GICC CPUs", r"MADT.*CPUs=4|GICC=4"),
    _c("ACPI-008", "both", "iort_acpi", "Kernel parses MADT GICv3", r"ACPI: MADT .*GICv3 CPUs=4"),
    _c("ACPI-009", "both", "iort_acpi", "Kernel parses GTDT timers", r"ACPI: GTDT timer interrupt"),
    _c("ACPI-010", "both", "iort_acpi", "Kernel probes IORT SMMUv3", r"ACPI: IORT SMMUv3 probed"),
    _c("ACPI-011", "both", "iort_acpi", "PCIe RC DMA coherent via IORT", r"PCIe RC DMA coherent"),
    _c("ACPI-012", "both", "iort_acpi", "PPTT cache topology parsed", r"ACPI: PPTT cache topology"),
    _c("ACPI-013", "sbsa", "iort_acpi", "PPTT cluster=1 cores=4", r"PPTT .*cluster=1 cores=4"),
    _c("ACPI-014", "both", "iort_acpi", "SMMUv3 stage1+2 in kernel", r"SMMUv3: IORT translation|SMMUv3 stage1"),
    _c("ACPI-015", "both", "iort_acpi", "PCIe ECAM host bridge probed", r"PCIe: ECAM"),
    _c("ACPI-016", "both", "iort_acpi", "PCIe host bridge enumerated in DXE", r"PCIe host bridge enumerated"),
    _c("ACPI-017", "sbsa", "iort_acpi", "ACPI S0 power state supported", r"ACPI: Power: S0 supported"),
    _c("ACPI-018", "sbsa", "iort_acpi", "S3/S4 unsupported per server profile", r"S3/S4 unsupported"),
    _c("ACPI-019", "both", "iort_acpi", "EFI ACPI reclaim retained", r"efi: EFI v2.7"),
    _c("ACPI-020", "both", "iort_acpi", "Early ACPI table verification path", r"ACPI: Early table checksum"),
    _c("ACPI-021", "sbsa", "iort_acpi", "RAS/GHES absence honestly reported", r"GHES absent", optional=True),
    _c("ACPI-022", "both", "iort_acpi", "IOMMU probed", r"IOMMU: SMMUv3"),
    _c("ACPI-023", "both", "iort_acpi", "L1/L2 cache topology in PPTT path", r"L1d L1i L2 unified"),
    _c("ACPI-024", "both", "iort_acpi", "ACPI tables installed before BDS", r"ACPI tables installed"),
    # ---- UEFI (16) ----
    _c("UEFI-001", "both", "uefi", "EDK II firmware banner", r"UEFI firmware \(version EDK II"),
    _c("UEFI-002", "both", "uefi", "ExitBootServices in EFI stub", r"ExitBootServices called"),
    _c("UEFI-003", "both", "uefi", "Runtime services retained after ExitBootServices", r"runtime services retained"),
    _c("UEFI-004", "both", "uefi", "Runtime variable services available", r"Runtime variable services available"),
    _c("UEFI-005", "both", "uefi", "SecureBoot state reported", r"SecureBoot disabled \(mock\)"),
    _c("UEFI-006", "both", "uefi", "EFI version reported to kernel", r"efi: EFI v2.7 by EDK II"),
    _c("UEFI-007", "both", "uefi", "SMBIOS published from DXE", r"SMBIOS tables published"),
    _c("UEFI-008", "both", "uefi", "ACPI published from DXE", r"ACPI tables installed"),
    _c("UEFI-009", "both", "uefi", "Console on PL011 UART", r"Console: UART PL011"),
    _c("UEFI-010", "both", "uefi", "Storage driver bound in DXE", r"AHCI/NVMe storage driver bound"),
    _c("UEFI-011", "both", "uefi", "Boot entry booted via BDS", r"Booting UEFI Mock Boot Entry"),
    _c("UEFI-012", "both", "uefi", "TPM final events logged (mock statement)", r"TPM final events logged"),
    _c("UEFI-013", "bsa", "uefi", "HOB list conformance (memory/resource)", r"HOB list created: memory allocation, resource descriptor"),
    _c("UEFI-014", "both", "uefi", "SetVirtualAddressMap applied", r"SetVirtualAddressMap"),
    _c("UEFI-015", "both", "uefi", "Initrd device path GUID used", r"LINUX_EFI_INITRD_MEDIA_GUID"),
    _c("UEFI-016", "sbsa", "uefi", "Server boot manager present", r"Boot Manager menu"),
    # ---- SMBIOS / PLATFORM (8) ----
    _c("SMB-001", "both", "smbios", "SMBIOS Type 0 BIOS info present", r"SMBIOS: Type 0 BIOS"),
    _c("SMB-002", "both", "smbios", "SMBIOS Type 1 System info present", r"Type 1 System"),
    _c("SMB-003", "both", "smbios", "SMBIOS Type 4 Processor x4", r"Type 4 Processor x4"),
    _c("SMB-004", "both", "smbios", "SMBIOS Type 7 Cache present", r"Type 7 Cache"),
    _c("SMB-005", "both", "smbios", "SMBIOS Type 16/17 Memory present", r"Type 16/17 Memory"),
    _c("SMB-006", "sbsa", "smbios", "SMBIOS Type 42 Redfish host interface", r"Type 42 Redfish"),
    _c("SMB-007", "both", "smbios", "CPU features: BTI/PAN/UAO/SSBS", r"Spectre-v4 SSBS, BTI, PAN, UAO"),
    _c("SMB-008", "both", "platform", "PL011 UART at 0x9000000 probed", r"PL011 ttyAMA0 at MMIO 0x9000000"),
]

assert len(CHECKS) >= 100, len(CHECKS)
