"""dockseal - zero-dependency Dockerfile security auditor.

Public API: parse_dockerfile, run_all_rules, audit_text_target, main.
"""

__version__ = "1.0.0"

from .parser import Instruction, parse_dockerfile, DockerfileParseError
from .rules import Finding, run_all_rules
from .report import AuditResult, audit_text_target, render_text, render_json
from .cli import main

__all__ = [
    "Instruction", "parse_dockerfile", "DockerfileParseError",
    "Finding", "run_all_rules",
    "AuditResult", "audit_text_target", "render_text", "render_json",
    "main", "__version__",
]
