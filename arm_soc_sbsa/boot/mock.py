"""Mock platform: Python state machine emulating TF-A (EL3) -> EDK II -> Linux.

No QEMU or firmware binaries required. Each milestone emits UART-style lines
that the ACS parser consumes, so the exact same checks run in both modes.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class Milestone(str, Enum):
    RESET = "RESET"
    BL1 = "BL1"
    BL2 = "BL2"
    BL31_EL3 = "BL31_EL3"
    BL33_UEFI_PEI = "BL33_UEFI_PEI"
    DXE = "DXE"
    BDS = "BDS"
    ACPI_SMBIOS_HANDOFF = "ACPI_SMBIOS_HANDOFF"
    LINUX_EFISTUB = "LINUX_EFISTUB"
    LINUX_KERNEL = "LINUX_KERNEL"
    LOGIN = "LOGIN"


MILESTONES: list[Milestone] = list(Milestone)

# UART line templates per milestone. ACS checks grep these patterns.
_LINES: dict[Milestone, list[str]] = {
    Milestone.RESET: [
        "[RESET] CPU0 released from reset vector EL3",
        "[RESET] GICv3 distributor/redistributor probed",
    ],
    Milestone.BL1: [
        "NOTICE: BL1: v2.10.0 (mock) Built : 00:00:00",
        "INFO:    BL1: RAM 0x40000000 - 0x4000ffff",
        "INFO:    BL1: Booting BL2",
    ],
    Milestone.BL2: [
        "NOTICE: BL2: v2.10.0 (mock)",
        "INFO:    BL2: Doing platform setup",
        "INFO:    BL2: Loading image id 1 at address 0x40060000",
        "INFO:    BL2: Loading image id 3 at address 0x44000000",
        "INFO:    BL2: Loading image id 5 at address 0x44100000",
    ],
    Milestone.BL31_EL3: [
        "NOTICE: BL31: v2.10.0 (mock)",
        "INFO:    GICv3 with legacy support detected",
        "INFO:    BL31: Initializing runtime services",
        "INFO:    BL31: Initializing BL32",
        "INFO:    BL31: Preparing for EL3 exit",
        "INFO:    PSCI: System ready, SMC forwarding enabled",
        "INFO:    EL3: Secure Monitor initialized, SMC handler installed",
    ],
    Milestone.BL33_UEFI_PEI: [
        "UEFI firmware (version EDK II mock, ArmVirtPkg)",
        "PEI: PEI core entry",
        "PEI: Memory discovered 0x40000000 size 0x80000000 (2 GiB)",
        "PEI: FV main 0x44000000",
        "PEI: HOB list created: memory allocation, resource descriptor",
    ],
    Milestone.DXE: [
        "DXE: DXE core entry",
        "DXE: GICv3 driver installed, interrupt controller ready",
        "DXE: Generic Timer initialized CNTFRQ=100000000 Hz",
        "DXE: PCIe host bridge enumerated bus 0-255 ECAM 0x20000000",
        "DXE: AHCI/NVMe storage driver bound",
        "DXE: Console: UART PL011 0x9000000 baud 115200",
        "DXE: SMBIOS tables published",
        "DXE: ACPI tables installed: RSDP XSDT MADT GTDT IORT PPTT SRAT SLIT HMAT",
    ],
    Milestone.BDS: [
        "BDS: Boot Device Selection phase",
        "BDS: Boot Manager menu, boot options enumerated",
        "[Bds]Booting UEFI Mock Boot Entry",
        "BDS: ExitBootServices preparation, watchdog timer set",
    ],
    Milestone.ACPI_SMBIOS_HANDOFF: [
        "ACPI: RSDP 0x47FF0000 000024 (v02 ARMLTD)",
        "ACPI: XSDT 0x47FE0040 00007C (v01 ARMLTD SBSAREF)",
        "ACPI: MADT 0x47FD0000 checksum OK GICv3 GICC=4 GICD ITS",
        "ACPI: GTDT 0x47FD1000 checksum OK CNTFRQ timer GSIV 27 30",
        "ACPI: IORT 0x47FD2000 checksum OK ITS group SMMUv3 PCIe RC",
        "ACPI: PPTT 0x47FD3000 checksum OK topology cluster=1 cores=4",
        "ACPI: SRAT SLIT HMAT present NUMA nodes=1",
        "SMBIOS: Type 0 BIOS, Type 1 System, Type 4 Processor x4, Type 7 Cache, Type 16/17 Memory, Type 38 IPMI absent, Type 42 Redfish host interface",
    ],
    Milestone.LINUX_EFISTUB: [
        "EFI stub: Booting Linux Kernel...",
        "EFI stub: Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID device path",
        "EFI stub: Exiting boot services...",
        "UEFI: ExitBootServices called, runtime services retained (SetVirtualAddressMap)",
        "UEFI: Runtime variable services available, SecureBoot disabled (mock)",
        "UEFI: EFI memory map handed to kernel, TPM final events logged",
    ],
    Milestone.LINUX_KERNEL: [
        "[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x410fd034]",
        "[    0.000000] Linux version 6.8.0-mock (aarch64)",
        "[    0.000000] efi: EFI v2.7 by EDK II",
        "[    0.000000] ACPI: Early table checksum verification disabled",
        "[    0.000000] ACPI: MADT 0x47FD0000 GICv3 CPUs=4 online",
        "[    0.000000] ACPI: GTDT timer interrupt 27 EL1 physical, 30 virtual",
        "[    0.000000] ACPI: IORT SMMUv3 probed, PCIe RC DMA coherent",
        "[    0.000000] ACPI: PPTT cache topology L1d L1i L2 unified",
        "[    0.000000] GICv3: GIC: Using split EOI/Deactivate mode",
        "[    0.000000] GICv3: ITS: allocated 65536 devices",
        "[    0.000000] arch_timer: cp15 timer(s) running at 100.00MHz (virt)",
        "[    0.000000] Memory: 2048 MiB available, memory model flat",
        "[    0.000000] NUMA: node 0 CPUs 0-3 memory 0x40000000-0xBFFFFFFF",
        "[    0.000000] PCIe: ECAM at 0x3F0000000 bus 00-ff, host bridge probed",
        "[    0.000000] SMMUv3: IORT translation, stage-2 bypass for RC",
        "[    0.010000] smp: Brought up 1 node, 4 CPUs SMP: total of 4 processors activated",
        "[    0.020000] CPU features: detected: GIC system register CPU interface",
        "[    0.020000] CPU features: detected: Spectre-v4 SSBS, BTI, PAN, UAO",
        "[    0.030000] Kernel command line: console=ttyAMA0 root=/dev/ram0",
        "[    0.040000] Memory block size: 128 MiB, memory hotplug not supported (mock)",
        "[    0.050000] Interrupt: SPI 32-991, SGI 0-15, PPI 16-31 partitioning OK",
        "[    0.060000] Timer: virtual timer IRQ 27, physical IRQ 30, hypervisor IRQ 26",
        "[    0.070000] Watchdog: SBSA Generic Watchdog at 0x2A440000 GSIV 90",
        "[    0.080000] UART: PL011 ttyAMA0 at MMIO 0x9000000 IRQ 33 enabled",
        "[    0.090000] PCIe: MSI via ITS, MSI-X supported, AER enabled",
        "[    0.100000] IOMMU: SMMUv3 stage1+2, PASID not advertised",
        "[    0.110000] ACPI: Power: S0 supported, S3/S4 unsupported (server profile)",
        "[    0.120000] RAS: GHES absent (mock), APEI not claimed",
        "[    0.130000] NUMA SRAT: PXM 0 -> APIC 0-3, memory affinity enabled",
    ],
    Milestone.LOGIN: [
        "[    1.000000] Run /init as init process",
        "Welcome to mock SBSA Linux (aarch64)",
        "sbsa login: root (automatic login)",
        "BOOT_COMPLETE milestone=LOGIN elapsed_mock=ok",
    ],
}


@dataclass
class BootResult:
    milestones: list[Milestone] = field(default_factory=list)
    uart_lines: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    success: bool = False

    @property
    def uart_text(self) -> str:
        return "\n".join(self.uart_lines) + ("\n" if self.uart_lines else "")


class BootStateMachine:
    """Strictly ordered milestone machine; skipping a state is an error."""

    def __init__(self, fail_at: Milestone | None = None):
        self._idx = -1
        self.fail_at = fail_at
        self.result = BootResult()
        self._listeners = []

    def on_milestone(self, fn):
        self._listeners.append(fn)

    @property
    def current(self) -> Milestone | None:
        return MILESTONES[self._idx] if self._idx >= 0 else None

    def advance(self, target: Milestone) -> None:
        expected = self._idx + 1
        if expected >= len(MILESTONES) or MILESTONES[expected] != target:
            raise ValueError(f"illegal transition {self.current} -> {target}, expected {MILESTONES[expected] if expected < len(MILESTONES) else None}")
        self._idx = expected
        if self.fail_at == target:
            raise RuntimeError(f"injected failure at {target.value}")
        self.result.milestones.append(target)
        self.result.uart_lines.extend(_LINES[target])
        for fn in self._listeners:
            fn(target)

    def run(self) -> BootResult:
        start = time.perf_counter()
        try:
            for m in MILESTONES:
                self.advance(m)
            self.result.success = True
        finally:
            self.result.elapsed_s = time.perf_counter() - start
        return self.result


def run_mock_boot(fail_at: Milestone | None = None) -> BootResult:
    return BootStateMachine(fail_at=fail_at).run()
