"""dockseal CLI.

Usage:
    dockseal [paths...]            # files with Dockerfiles or directories
    dockseal --json paths...       # machine-readable output
    dockseal --min-grade B path    # CI gate: grade below B -> BLOCK

A path that is a directory is scanned for files named Dockerfile
(case-sensitive, plus any *.Dockerfile). Directory targets additionally
check for a .dockerignore next to each Dockerfile.

Exit codes:
    0   PASS  - no findings
    1   WARN  - findings, none blocking
    2   BLOCK - critical finding or score >= 50 (or grade below --min-grade)
    64  usage error / unreadable input
"""

import argparse
import os
import sys
from typing import List, Optional

from .report import AuditResult, audit_text_target, render_json, render_text, worst_verdict

EXIT_PASS, EXIT_WARN, EXIT_BLOCK, EXIT_USAGE = 0, 1, 2, 64

_GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]


def _collect_dockerfiles(path: str) -> List[str]:
    """Yield Dockerfile paths for a file or directory target."""
    if os.path.isfile(path):
        return [path]
    found = []
    for root, dirs, files in os.walk(path):
        # keep scans fast and out of vendored trees
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build")]
        for name in files:
            if (name == "Dockerfile" or name.endswith(".Dockerfile")
                    or name.startswith("Dockerfile.")):
                found.append(os.path.join(root, name))
    return sorted(found)


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        print(f"dockseal: cannot read {path}: {exc}", file=sys.stderr)
        return None


def audit_path(path: str) -> List[AuditResult]:
    results: List[AuditResult] = []
    dockerfiles = _collect_dockerfiles(path)
    if not dockerfiles:
        results.append(AuditResult(path, [], [], 0, "A+", "PASS",
                                   error="no Dockerfile found"))
        return results
    is_dir = os.path.isdir(path)
    for df in dockerfiles:
        text = _read(df)
        if text is None:
            results.append(AuditResult(df, [], [], 0, "A+", "PASS",
                                       error="unreadable"))
            continue
        dockerignore = None
        if is_dir:
            context_dir = os.path.dirname(df) or "."
            dockerignore = os.path.exists(os.path.join(context_dir, ".dockerignore"))
        results.append(audit_text_target(df, text, dockerignore))
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="dockseal",
        description="Zero-dependency Dockerfile security auditor (root users, baked-in "
                    "secrets, unpinned bases, pipe-to-shell, docker.sock...).")
    parser.add_argument("paths", nargs="*", default=["Dockerfile"],
                        help="Dockerfile(s) or directories containing them (default: ./Dockerfile)")
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    parser.add_argument("--min-grade", default=None,
                        choices=_GRADE_ORDER,
                        help="fail (exit 2) if the overall grade is below this")
    args = parser.parse_args(argv)

    if args.min_grade:
        missing = [p for p in args.paths if not os.path.exists(p)]
        if missing:
            print("dockseal: min-grade requires auditable paths; not found: "
                  + ", ".join(missing), file=sys.stderr)
            return EXIT_USAGE

    results: List[AuditResult] = []
    saw_error = False
    for p in args.paths:
        if not os.path.exists(p):
            print(f"dockseal: path not found: {p}", file=sys.stderr)
            saw_error = True
            continue
        results.extend(audit_path(p))

    if saw_error:
        return EXIT_USAGE
    if not results:
        print("dockseal: nothing to audit", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(render_json(results))
    else:
        for r in results:
            print(render_text(r), end="")

    # nothing auditable at all -> usage-grade failure, do not fake a PASS
    if all(r.error for r in results):
        return EXIT_USAGE

    verdict = worst_verdict(results)
    exit_code = {"PASS": EXIT_PASS, "WARN": EXIT_WARN, "BLOCK": EXIT_BLOCK}[verdict]

    if args.min_grade:
        worst = min((r.grade for r in results if not r.error), default="A+")
        if _GRADE_ORDER.index(worst) > _GRADE_ORDER.index(args.min_grade):
            print(f"dockseal: grade {worst} below required {args.min_grade}",
                  file=sys.stderr)
            exit_code = max(exit_code, EXIT_BLOCK)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
