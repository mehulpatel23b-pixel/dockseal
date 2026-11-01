"""Aggregation + rendering: score, grade, verdict, text/JSON report."""

import json
from dataclasses import dataclass, field
from typing import List

from .parser import Instruction
from .rules import Finding, run_all_rules

# score -> grade bands (mirrors hdrscope-style severity curves)
_GRADE_BANDS = [(0, "A+"), (3, "A"), (8, "B"), (15, "C"), (30, "D")]

BLOCK_SCORE = 50


def grade_for(score: int) -> str:
    grade = "F"
    for threshold, g in _GRADE_BANDS:
        if score <= threshold:
            grade = g
            break
    return grade


@dataclass
class AuditResult:
    target: str
    instructions: List[Instruction]
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = "A+"
    verdict: str = "PASS"      # PASS | WARN | BLOCK
    error: str = ""

    @property
    def n_critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")


def audit_text_target(target_label: str, text: str, dockerignore_exists=None) -> AuditResult:
    """Parse + audit one Dockerfile given as source text."""
    from .parser import DockerfileParseError, parse_dockerfile
    try:
        instructions = parse_dockerfile(text)
    except DockerfileParseError as exc:
        return AuditResult(target_label, [], [], 0, "A+", "PASS", error=str(exc))
    findings = run_all_rules(instructions, dockerignore_exists)
    return _finalize(target_label, instructions, findings)


def _finalize(target: str, instructions: List[Instruction], findings: List[Finding]) -> AuditResult:
    score = sum(f.weight for f in findings)
    has_critical = any(f.severity == "CRITICAL" for f in findings)
    if score == 0:
        verdict = "PASS"
    elif has_critical or score >= BLOCK_SCORE:
        verdict = "BLOCK"
    else:
        verdict = "WARN"
    return AuditResult(target, instructions, findings, score, grade_for(score), verdict)


# --------------------------------------------------------------------------- render

_SEV_COLOR = {"CRITICAL": "41;97", "HIGH": "91", "MEDIUM": "93", "LOW": "94"}


def render_text(result: AuditResult, use_color: bool = False) -> str:
    if result.error:
        return f"dockseal: {result.target}: {result.error}\n"

    out = []
    out.append("Dockseal - Dockerfile security audit")
    out.append("=" * 60)
    out.append(f"Target   : {result.target}")
    out.append(f"Verdict  : {result.verdict}   Score: {result.score}   Grade: {result.grade}")
    out.append(f"Findings : {len(result.findings)}"
               f"  (critical: {result.n_critical})")
    out.append("=" * 60)

    if not result.findings:
        out.append("")
        out.append("No findings. Image build hygiene looks clean.")
        out.append("Next hardening step (optional): digest-pin every FROM for")
        out.append("tag-drift immunity.")
        return "\n".join(out) + "\n"

    out.append("")
    for f in result.findings:
        sev = f.severity
        head = f"[{sev}] {f.rule_id}: {f.title}"
        out.append(head)
        loc = f"line {f.lines[0]}" if f.lines else "file-level"
        if f.lines and len(f.lines) > 1:
            loc = "lines " + ",".join(str(l) for l in f.lines[:4])
        out.append(f"  Where  : {loc}  (weight {f.weight})")
        out.append(f"  Code   : {f.evidence}")
        out.append(f"  Fix    : {f.fix}")
        out.append("")
    return "\n".join(out) + "\n"


def render_json(results: List[AuditResult]) -> str:
    payload = {
        "tool": "dockseal",
        "version": "1.0.0",
        "targets": [
            {
                "target": r.target,
                "verdict": r.verdict,
                "score": r.score,
                "grade": r.grade,
                "n_findings": len(r.findings),
                "n_critical": r.n_critical,
                "error": r.error or None,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in results
        ],
        "worst_verdict": worst_verdict(results),
    }
    return json.dumps(payload, indent=2)


def worst_verdict(results: List[AuditResult]) -> str:
    order = {"PASS": 0, "WARN": 1, "BLOCK": 2}
    worst = "PASS"
    for r in results:
        if r.error:
            continue
        if order[r.verdict] > order[worst]:
            worst = r.verdict
    return worst
