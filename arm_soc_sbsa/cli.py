"""CLI: `arm-soc-sbsa` subcommands.

  boot-run --mode mock|qemu [--out DIR]
  tables gen|validate [--out-dir DIR]
  redfish serve|snapshot [--port N]
  acs run --suite sbsa|bsa --report json [--log FILE] [--out FILE]
  bench
  selftest
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _tables_gen(out_dir: Path) -> dict:
    from .tables.acpi import build_all, parse_table
    from .tables.smbios import build_smbios

    out_dir.mkdir(parents=True, exist_ok=True)
    blobs = build_all()
    blobs["SMBIOS"] = build_smbios()
    info = {}
    for name, blob in blobs.items():
        (out_dir / f"{name}.dat").write_bytes(blob)
        if name != "SMBIOS":
            info[name] = parse_table(blob)
    return info


def cmd_boot_run(args) -> int:
    out = Path(args.out or "out")
    out.mkdir(parents=True, exist_ok=True)
    if args.mode == "mock":
        from .boot.mock import BootStateMachine
        from .redfish.service import RedfishService

        svc = RedfishService()
        sm = BootStateMachine()
        sm.on_milestone(svc.record_milestone)
        result = sm.run()
        (out / "uart.log").write_text(result.uart_text)
        (out / "redfish-snapshot.json").write_text(json.dumps(svc.snapshot(), indent=2))
        print(f"mock boot: success={result.success} milestones={len(result.milestones)} elapsed={result.elapsed_s:.3f}s")
        print(f"uart log: {out / 'uart.log'}")
        return 0 if result.success else 1
    else:
        from .boot.qemu_runner import run_qemu, build_qemu_command

        cmd = build_qemu_command(log_file=str(out / "uart.log"))
        print("QEMU command:", " ".join(cmd))
        try:
            run_qemu(log_file=str(out / "uart.log"))
        except RuntimeError as e:
            print(f"qemu mode unavailable: {e}", file=sys.stderr)
            return 2
        return 0


def cmd_tables(args) -> int:
    out_dir = Path(args.out_dir or "out/tables")
    if args.action == "gen":
        info = _tables_gen(out_dir)
        print(json.dumps(info, indent=2))
        print(f"wrote tables to {out_dir}")
        return 0
    else:  # validate
        from .tables.acpi import parse_table, validate_blob
        from .tables.smbios import parse_smbios

        errors: list[str] = []
        found = sorted(out_dir.glob("*.dat")) if out_dir.exists() else []
        if not found:
            # validate freshly generated in-memory tables
            from .tables.acpi import build_all
            for name, blob in build_all().items():
                errs = validate_blob(blob)
                print(f"{name}: {'OK' if not errs else errs}")
                errors += errs
            return 0 if not errors else 1
        for p in found:
            blob = p.read_bytes()
            if p.stem == "SMBIOS":
                structs = parse_smbios(blob)
                ok = bool(structs) and structs[-1]["type"] == 127
                print(f"SMBIOS: structures={len(structs)} end-of-table={ok}")
                if not ok:
                    errors.append("SMBIOS missing end-of-table")
            else:
                errs = validate_blob(blob)
                info = parse_table(blob)
                print(f"{p.stem}: checksum_ok={info['checksum_ok']} length_ok={info['length_ok']} errors={errs}")
                errors += errs
        return 0 if not errors else 1


def cmd_redfish(args) -> int:
    from .redfish.service import RedfishService, create_server
    from .boot.mock import BootStateMachine

    svc = RedfishService()
    sm = BootStateMachine()
    sm.on_milestone(svc.record_milestone)
    sm.run()
    if args.action == "snapshot":
        print(json.dumps(svc.snapshot(), indent=2))
        return 0
    server = create_server(svc, port=args.port)
    print(f"Redfish shim on http://127.0.0.1:{args.port}/redfish/v1 (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_acs(args) -> int:
    from .acs.runner import run_checks
    from .boot.mock import run_mock_boot
    from .tables.acpi import build_all, parse_table

    if args.log:
        uart = Path(args.log).read_text(errors="replace")
    else:
        uart = run_mock_boot().uart_text
    table_infos = [parse_table(b) for b in build_all().values()]
    report = run_checks(uart, suite=args.suite, table_infos=table_infos)
    text = report.to_json() if args.report == "json" else str(report.to_dict())
    if args.out:
        Path(args.out).write_text(text)
    print(text if args.report == "json" else f"{report.suite}: {report.passed}/{report.total} PASS fail={report.failed} skipped={report.skipped} in {report.elapsed_s:.3f}s")
    if args.out:
        print(f"report: {args.out}")
    return 0 if report.failed == 0 else 1


def cmd_bench(args) -> int:
    from .acs.runner import run_checks
    from .boot.mock import run_mock_boot
    from .tables.acpi import build_all, parse_table

    start = time.perf_counter()
    uart = run_mock_boot().uart_text
    table_infos = [parse_table(b) for b in build_all().values()]
    report = run_checks(uart, suite="all", table_infos=table_infos)
    wall = time.perf_counter() - start
    print(f"BENCH suite=all checks={report.total} passed={report.passed} failed={report.failed} skipped={report.skipped} wall={wall:.3f}s (acs_parse={report.elapsed_s:.3f}s)")
    return 0 if report.failed == 0 else 1


def cmd_selftest(args) -> int:
    import subprocess
    return subprocess.run([sys.executable, "-m", "pytest", "-q"]).returncode


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="arm-soc-sbsa", description="Arm SoC Boot and UEFI/BIOS Compliance Lab")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("boot-run")
    b.add_argument("--mode", choices=["mock", "qemu"], default="mock")
    b.add_argument("--out", default="out")
    b.set_defaults(fn=cmd_boot_run)

    t = sub.add_parser("tables")
    t.add_argument("action", choices=["gen", "validate"])
    t.add_argument("--out-dir", default="out/tables")
    t.set_defaults(fn=cmd_tables)

    r = sub.add_parser("redfish")
    r.add_argument("action", choices=["serve", "snapshot"])
    r.add_argument("--port", type=int, default=8000)
    r.set_defaults(fn=cmd_redfish)

    a = sub.add_parser("acs")
    a_sub = a.add_subparsers(dest="acs_cmd", required=True)
    run = a_sub.add_parser("run")
    run.add_argument("--suite", choices=["sbsa", "bsa", "all"], default="sbsa")
    run.add_argument("--report", choices=["json", "text"], default="json")
    run.add_argument("--log", default=None)
    run.add_argument("--out", default=None)
    run.set_defaults(fn=cmd_acs)

    bench = sub.add_parser("bench")
    bench.set_defaults(fn=cmd_bench)

    st = sub.add_parser("selftest")
    st.set_defaults(fn=cmd_selftest)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
