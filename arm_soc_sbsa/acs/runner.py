from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict

from .checks import CHECKS, Check


@dataclass
class CheckResult:
    id: str
    suite: str
    category: str
    description: str
    status: str  # PASS | FAIL | SKIPPED
    detail: str = ""


@dataclass
class AcsReport:
    suite: str
    results: list[CheckResult] = field(default_factory=list)
    elapsed_s: float = 0.0

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.status == "SKIPPED")

    @property
    def total(self) -> int:
        return len(self.results)

    def to_dict(self) -> dict:
        return {
            "suite": self.suite, "total": self.total, "passed": self.passed,
            "failed": self.failed, "skipped": self.skipped, "elapsed_s": round(self.elapsed_s, 4),
            "results": [asdict(r) for r in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def run_checks(uart_text: str, suite: str = "sbsa", table_infos: list[dict] | None = None) -> AcsReport:
    """Parse UART text (+ optional parsed ACPI tables) and assert each check.

    A check PASSes if its pattern is found. If the log is empty the check is
    SKIPPED (no artifact), otherwise a missing pattern is a FAIL. Table checks
    use parsed table metadata when supplied, else fall back to UART lines.
    """
    start = time.perf_counter()
    selected: list[Check] = [c for c in CHECKS if suite == "all" or c.suite == suite or c.suite == "both"]
    table_text = ""
    if table_infos:
        table_text = "\n".join(
            f"TABLE {t.get('signature')} cpus={t.get('num_cpus')} gicc={t.get('gicc_count')} checksum_ok={t.get('checksum_ok')}"
            for t in table_infos
        )
    haystack = uart_text + "\n" + table_text
    results: list[CheckResult] = []
    for c in selected:
        if not uart_text.strip() and not table_infos:
            results.append(CheckResult(c.id, c.suite, c.category, c.description, "SKIPPED", "no log/artifact supplied"))
            continue
        m = c.pattern.search(haystack)
        if m:
            results.append(CheckResult(c.id, c.suite, c.category, c.description, "PASS", f"matched: {m.group(0)[:80]}"))
        elif c.optional:
            results.append(CheckResult(c.id, c.suite, c.category, c.description, "SKIPPED", "optional pattern absent"))
        else:
            results.append(CheckResult(c.id, c.suite, c.category, c.description, "FAIL", f"pattern not found: {c.pattern.pattern[:80]}"))
    return AcsReport(suite=suite, results=results, elapsed_s=time.perf_counter() - start)
