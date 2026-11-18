#!/usr/bin/env bash
# Real QEMU sbsa-ref run. Requires:
#   - qemu-system-aarch64 (>= 8.0, provides the sbsa-ref machine)
#   - EDK II firmware for sbsa-ref (QEMU_EFI.fd), e.g. built from edk2-platforms
#     (Platform/Qemu/SbsaQemu) or a distro edk2 firmware package
#   - Trusted Firmware-A is integrated into the sbsa-ref firmware image flow;
#     on sbsa-ref QEMU emulates the secure world handoff to EDK II.
# This script is shipped for reference/lab use; CI uses --mode mock instead.
set -euo pipefail
FIRMWARE="${FIRMWARE:-QEMU_EFI.fd}"
KERNEL="${KERNEL:-}"
INITRD="${INITRD:-}"
mkdir -p out
ARGS=(
  qemu-system-aarch64
  -machine sbsa-ref
  -cpu max
  -smp 4
  -m 4G
  -nographic
  -bios "$FIRMWARE"
  -serial file:out/qemu-uart.log
  -monitor none
)
if [[ -n "$KERNEL" ]]; then
  ARGS+=(-kernel "$KERNEL" -append "console=ttyAMA0 root=/dev/ram0")
fi
if [[ -n "$INITRD" ]]; then
  ARGS+=(-initrd "$INITRD")
fi
echo "+ ${ARGS[*]}"
exec "${ARGS[@]}"
