"""QEMU sbsa-ref runner. Builds the real command line; actually launching
QEMU requires qemu-system-aarch64 plus TF-A/EDK II firmware blobs, which are
external artifacts (see scripts/run_qemu_sbsa.sh and README limitations).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def build_qemu_command(
    firmware: str = "QEMU_EFI.fd",
    cpu: str = "max",
    smp: int = 4,
    mem: str = "4G",
    kernel: str | None = None,
    initrd: str | None = None,
    append: str = "console=ttyAMA0 root=/dev/ram0",
    log_file: str = "qemu-uart.log",
) -> list[str]:
    cmd = [
        "qemu-system-aarch64",
        "-machine", "sbsa-ref",
        "-cpu", cpu,
        "-smp", str(smp),
        "-m", mem,
        "-nographic",
        "-bios", firmware,
        "-serial", f"file:{log_file}",
        "-monitor", "none",
    ]
    if kernel:
        cmd += ["-kernel", kernel]
    if initrd:
        cmd += ["-initrd", initrd]
    if kernel:
        cmd += ["-append", append]
    return cmd


def run_qemu(**kwargs) -> subprocess.CompletedProcess:
    if shutil.which("qemu-system-aarch64") is None:
        raise RuntimeError(
            "qemu-system-aarch64 not found. Install QEMU or use --mode mock. "
            "See scripts/run_qemu_sbsa.sh for the full firmware setup."
        )
    firmware = kwargs.get("firmware", "QEMU_EFI.fd")
    if not Path(firmware).exists():
        raise RuntimeError(f"firmware blob not found: {firmware} (expected EDK II QEMU_EFI.fd for sbsa-ref)")
    cmd = build_qemu_command(**kwargs)
    return subprocess.run(cmd, check=False, timeout=kwargs.get("timeout", 120))
