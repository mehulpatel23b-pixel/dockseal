"""Dockerfile parser for dockseal.

Parses a Dockerfile into a list of :class:`Instruction` objects, handling
line continuations (trailing backslash), comments, and multi-stage builds.
No third-party dependencies: this is a deliberate, pragmatic Dockerfile
parser, not a full grammar - it covers the constructs that appear in real
build files (see the honesty section of the README for the limits).
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Instruction:
    """One Dockerfile instruction (possibly spanning several physical lines)."""

    cmd: str              # upper-cased instruction keyword, e.g. "RUN"
    value: str            # everything after the keyword, continuations joined with a space
    start_line: int       # first physical line (1-based)
    end_line: int         # last physical line (1-based)
    stage: int            # index of the build stage this instruction belongs to (0-based)
    raw: str = field(default="")   # original joined text (for evidence)

    def is_cmd(self, *names: str) -> bool:
        return self.cmd in names


class DockerfileParseError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    """Remove trailing comments that are not inside quotes.

    Docker treats '#' as a comment only at the start of a line or after
    whitespace, unless it appears inside a quoted string. We do a
    quote-aware scan which is good enough for real Dockerfiles.
    """
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line


def parse_dockerfile(text: str) -> List[Instruction]:
    """Parse Dockerfile source text into instructions.

    Raises :class:`DockerfileParseError` on empty input or a file that
    does not look like a Dockerfile at all.
    """
    instructions: List[Instruction] = []
    stage = 0
    saw_any = False

    pending: Optional[List[str]] = None      # accumulated physical lines of a continued instruction
    pending_start: int = 0

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line).strip()

        if not line:
            continue

        cont = line.endswith("\\")
        body = line[:-1].rstrip() if cont else line

        if pending is None:
            if cont:
                pending = [body]
                pending_start = lineno
                continue
            logical = body
            start_line = end_line = lineno
        else:
            # parser directives can only appear on their own line; a
            # continuation keeps accumulating regardless of content
            pending.append(body)
            if not cont:
                logical = " ".join(p for p in pending if p)
                start_line, end_line = pending_start, lineno
                pending = None
            else:
                continue

        parts = logical.strip().split(None, 1)
        if not parts or not parts[0]:
            continue
        cmd = parts[0].upper()
        value = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "FROM":
            # every FROM starts a new build stage
            if instructions:
                stage += 1
            instructions.append(Instruction("FROM", value, start_line, end_line, stage, logical))
            saw_any = True
            continue

        if cmd == "PARSER_DIRECTIVE" or cmd.startswith("#"):
            # parser directives handled above as comments; ignore gracefully
            continue

        if not _is_instruction(cmd):
            # Unknown instruction: keep it (rules may point at it) but flag nothing here.
            instructions.append(Instruction(cmd, value, start_line, end_line, stage, logical))
            continue

        instructions.append(Instruction(cmd, value, start_line, end_line, stage, logical))
        saw_any = True

    if not saw_any and not instructions:
        raise DockerfileParseError("no Dockerfile instructions found in input")

    return instructions


_KNOWN = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD",
    "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD",
    "STOPSIGNAL", "HEALTHCHECK", "SHELL",
}


def _is_instruction(cmd: str) -> bool:
    return cmd in _KNOWN
