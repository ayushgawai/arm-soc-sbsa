# arm-soc-sbsa — Arm SoC Boot and UEFI/BIOS Compliance Lab

A pre-silicon bring-up and compliance framework for an Armv9/AArch64 server SoC.
It drives a Trusted Firmware-A (EL3) → EDK II UEFI (PEI/DXE) → ACPI + SMBIOS →
Linux boot chain, generates and validates custom ACPI/SMBIOS tables, exposes an
OpenBMC-style Redfish management shim, and runs a subset of Arm SBSA/BSA
architecture compliance checks against captured UART logs — on a laptop, with
no QEMU or silicon required (mock mode), or against QEMU `sbsa-ref` when
firmware blobs are available.

## Design

```
                         arm-soc-sbsa
  ┌────────────────────────────────────────────────────────────────┐
  │  CLI  arm-soc-sbsa boot-run | tables | redfish | acs | bench   │
  └──────┬──────────────┬───────────────┬──────────────┬───────────┘
         │              │               │              │
         ▼              ▼               ▼              ▼
  ┌─────────────┐ ┌────────────┐ ┌─────────────┐ ┌──────────────┐
  │ Boot chain  │ │ ACPI/SMBIOS│ │ Redfish shim│ │ ACS runner   │
  │ runner      │ │ generator  │ │ (http.server│ │ 112 checks   │
  │             │ │            │ │  stdlib)    │ │ SBSA + BSA   │
  │ mock: state │ │ MADT GTDT  │ │ /redfish/v1 │ │              │
  │ machine     │ │ IORT PPTT  │ │ Systems/1/  │ │ parse UART / │
  │ EL3→PEI→DXE │ │ + SMBIOS   │ │ Bios, SEL   │ │ table blobs, │
  │ →BDS→Linux  │ │ .dat blobs │ │ event log   │ │ assert regex │
  │             │ │ round-trip │ │             │ │ + table meta │
  │ qemu: sbsa- │ │ + checksum │ │ milestones─►│ │              │
  │ ref command │ │ validator  │ │ SEL events  │ │ PASS/FAIL/   │
  └──────┬──────┘ └──────┬─────┘ └──────▲──────┘ │ SKIPPED JSON │
         │ UART log      │ .dat         │ events └──────┬───────┘
         └───────────────┴──────────────┴───────────────┘
                                 │
                                 ▼
                    out/uart.log, out/*.json reports
                    (CI: GitHub Actions, mock mode)
```

### Module design table

| Module | Input | Output | Failure modes |
|---|---|---|---|
| `arm_soc_sbsa/boot/mock.py` | — (or injected `fail_at`) | Ordered milestones + UART text (`BootResult`) | Illegal state transition raises `ValueError`; injected failure raises `RuntimeError` |
| `arm_soc_sbsa/boot/qemu_runner.py` | Firmware `QEMU_EFI.fd`, optional kernel/initrd | QEMU `sbsa-ref` process, `uart.log` | Missing `qemu-system-aarch64` or firmware → clear `RuntimeError`, CLI exit 2 |
| `arm_soc_sbsa/tables/acpi.py` | CPU count, GIC/timer parameters | Binary MADT/GTDT/IORT/PPTT `.dat`, parsed dicts | Bad checksum/length, missing GICC/GICD/IORT nodes → validator error list |
| `arm_soc_sbsa/tables/smbios.py` | CPU count | SMBIOS blob (Types 0/1/4/127) | Missing end-of-table detected by parser/validator |
| `arm_soc_sbsa/redfish/service.py` | Boot milestones | `/redfish/v1`, `Systems/1`, `Systems/1/Bios`, SEL/EventLog JSON; ordered events | Unknown path → Redfish `GeneralError` 404; port bind errors surface from `http.server` |
| `arm_soc_sbsa/acs/` | UART text + parsed ACPI tables, suite (`sbsa`/`bsa`/`all`) | `AcsReport` (JSON: pass/fail/skipped per check) | Empty artifact → all SKIPPED; missing pattern → FAIL; optional checks → SKIPPED |
| `arm_soc_sbsa/cli.py` | CLI args | Files under `out/`, JSON on stdout, exit codes | Non-zero exit on failed boot / failed checks / unavailable QEMU |

## Quick start

```bash
pip install -e ".[dev]"

# 1. Mock boot (no QEMU needed) — TF-A -> EDK II -> ACPI/SMBIOS -> Linux
arm-soc-sbsa boot-run --mode mock --out out
cat out/uart.log

# 2. Generate + validate ACPI/SMBIOS tables (binary .dat, round-trip parsed)
arm-soc-sbsa tables gen --out-dir out/tables
arm-soc-sbsa tables validate --out-dir out/tables

# 3. Redfish shim: snapshot, or serve HTTP
arm-soc-sbsa redfish snapshot
arm-soc-sbsa redfish serve --port 8000
#   curl http://127.0.0.1:8000/redfish/v1
#   curl http://127.0.0.1:8000/redfish/v1/Systems/1/Bios
#   curl http://127.0.0.1:8000/redfish/v1/Managers/1/LogServices/Sel/Entries

# 4. SBSA/BSA compliance checks (112 checks) against mock or captured logs
arm-soc-sbsa acs run --suite sbsa --report json --out out/acs-sbsa.json
arm-soc-sbsa acs run --suite bsa  --report json --out out/acs-bsa.json
arm-soc-sbsa acs run --suite all --report json --log samples/sample_uart.log

# 5. Real QEMU sbsa-ref (requires qemu-system-aarch64 + QEMU_EFI.fd)
arm-soc-sbsa boot-run --mode qemu --out out
# or: FIRMWARE=/path/QEMU_EFI.fd KERNEL=/path/Image bash scripts/run_qemu_sbsa.sh
```

## Tests and benchmark

```bash
python -m pytest -q        # 19 tests
arm-soc-sbsa selftest      # same, via the CLI
arm-soc-sbsa bench         # full mock ACS regression + wall time
```

Measured sanity run on the development laptop (Windows 11, Python 3.12,
mock mode — honest, scaled-down numbers, not a silicon result):

```
$ python -m pytest -q
19 passed in 0.76s

$ arm-soc-sbsa bench        (via test_cli_tables_and_bench, -s)
BENCH suite=all checks=112 passed=112 failed=0 skipped=0 wall=0.001s (acs_parse=0.001s)
```

The mock ACS core (boot-log generation + 112 pattern/table assertions) is
sub-millisecond-to-milliseconds; the full test suite including HTTP Redfish
tests completes in under a second. A full mock regression therefore reports
in well under a minute — the CI workflow runs exactly this on every push.

## Compliance checks

112 checks in `arm_soc_sbsa/acs/checks.py`, across boot (22), memory (20),
interrupts/GIC/timer (22), IORT/ACPI (24), UEFI (16) and SMBIOS/platform (8).
Each check is an explicit pattern/table assertion over the captured UART log
and parsed ACPI metadata, reported as PASS / FAIL / SKIPPED with the matched
(or missing) pattern. SBSA and BSA suites share `both` checks and add their
suite-specific ones (`acs run --suite sbsa|bsa|all`).

## Limitations (honest)

- **Host-simulated and QEMU-only; no silicon.** Mock mode is a Python state
  machine that *emulates* TF-A/EDK II/Linux milestones and UART text — it does
  not execute real firmware. QEMU mode needs externally built TF-A/EDK II
  (`QEMU_EFI.fd` for `sbsa-ref`) and a kernel; neither is bundled.
- **Check subset, not the full commercial/official ACS.** This is 112
  log/table assertions modelled on SBSA/BSA themes. The official Arm ACS runs
  UEFI-shell and bare-metal exerciser code on hardware/FVP and is far larger;
  passing here does **not** imply SBSA/BSA certification.
- **ACPI tables are teaching models.** MADT/GTDT/IORT/PPTT/SMBIOS are emitted
  as binary blobs with correct lengths/checksums and round-trip parsers, but
  fields are simplified vs. ACPI 6.5 / SMBIOS 3.x, AML (DSDT/SSDT) is out of
  scope, and production tables should come from EDK II + iASL.
- **Redfish shim is a subset.** Read-only GET resources, an in-memory SEL,
  and a static BIOS attribute model; no auth, no PATCH/actions, no persistence.
- GTDT CNTFRQ is carried in a model field (MHz) for round-trip testing; the
  mock timer frequency is asserted from UART text as well.

## Layout

```
arm_soc_sbsa/
  boot/      mock state machine + QEMU sbsa-ref runner
  tables/    ACPI (MADT/GTDT/IORT/PPTT) + SMBIOS generation/validation
  redfish/   OpenBMC-style Redfish service (stdlib http.server)
  acs/       112 SBSA/BSA check definitions + runner
  cli.py     arm-soc-sbsa entry point
tests/       table, boot, ACS parser, Redfish and CLI tests
samples/     sample_uart.log (recorded mock boot, used by parser tests)
scripts/     run_qemu_sbsa.sh
.github/     CI running the mock regression
```

## License

MIT — see `LICENSE`.
