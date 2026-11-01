"""dockseal security rules.

Each rule maps a class of real-world Dockerfile mistakes to a finding:
the incidents that made these rules are documented in the README.
Rules are pure functions over the parsed instruction list (plus optional
context such as whether the build directory has a .dockerignore file).
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from .parser import Instruction

# --------------------------------------------------------------------------- finding


@dataclass
class Finding:
    rule_id: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    weight: int
    title: str
    fix: str
    evidence: str           # masked, human-readable evidence
    lines: List[int]        # physical line numbers (1-based)

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "weight": self.weight,
            "title": self.title,
            "fix": self.fix,
            "evidence": self.evidence,
            "lines": self.lines,
        }


WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

# --------------------------------------------------------------------------- helpers

# NOTE: no \\b anchors - "OPENAI_API_KEY" must match, and \\b fails around "_"
_SECRET_NAMES = re.compile(
    r"(?i)(api[_-]?key|secret|password|passwd|pwd|tokens?|credentials?"
    r"|access[_-]?key|private[_-]?key|client[_-]?secret|signing[_-]?key|auth[_-]?token)"
)

# values that look like real material vs obvious placeholders/templates
_SECRETISH_VALUE = re.compile(
    r"(?i)(sk-[a-z0-9]{12,}|ghp_[a-z0-9]{16,}|github_pat_[a-z0-9_]{16,}|akia[0-9a-z]{16}"
    r"|-----begin[a-z ]*(rsa|ec|dsa|openpgp)? *private key|xox[bap]-[a-z0-9-]{10,}"
    r"|eyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,})"
)

# loose but useful: assignment of a long literal to a secret-sounding name
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_PIPE_SHELL = re.compile(
    r"(?i)\b(curl|wget)\b[^|;&]*(\||\|\||&&)\s*(/bin/)?(ba)?sh\b"
)

_SENSITIVE_FILES = re.compile(
    r"(?i)(^|[/\"'])"                                     # start of token or path sep
    r"(\.env($|\.)|id_rsa|id_dsa|id_ed25519|\w+\.(pem|key|p12|pfx)$|\.npmrc|\.netrc|credentials\.json|service[_-]?account[^/]*\.json)"
)

_DOCKER_SOCK = re.compile(r"/?var/run/docker\.sock")

_APT_INSTALL = re.compile(r"(?i)\bapt-get\s+(install|upgrade)\b")

_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")
_LAST_TAG = re.compile(r"(?i):latest\b|^scratch$")


def _final_stage(instructions: List[Instruction]) -> int:
    """Index of the final build stage (the image that actually ships)."""
    return max(i.stage for i in instructions) if instructions else 0


def _last_user_lines(instructions: List[Instruction], stage: int) -> List[Instruction]:
    return [i for i in instructions if i.is_cmd("USER") and i.stage == stage]


def mask(value: str) -> str:
    """Mask secret material: keep a 4-char prefix so findings stay recognizable."""
    def _sub(m):
        s = m.group(0)
        return s[:4] + "..." + "<masked>" if len(s) > 8 else "<masked>"

    masked = _SECRETISH_VALUE.sub(_sub, value)
    if len(masked) > 96:
        masked = masked[:93] + "..."
    return masked


# --------------------------------------------------------------------------- rules

def check_from_pinning(ins: List[Instruction]) -> List[Finding]:
    """DS-001 unpinned or :latest base + DS-002 tag-pinned without digest."""
    findings: List[Finding] = []
    for i in ins:
        if not i.is_cmd("FROM"):
            continue
        image = re.sub(r"(?i)\s+as\s+\w+$", "", i.value).strip()
        base = image.split("--platform=", 1)[-1].strip()
        if base.lower() == "scratch":
            continue  # the empty base image: nothing to pin
        if _DIGEST.search(base):
            continue  # digest-pinned: gold standard
        if _LAST_TAG.search(base) or ":" not in base:
            findings.append(Finding(
                "DS-001", "HIGH", WEIGHTS["HIGH"],
                "Unpinned base image" + (" (`:latest`)" if ":" in base else " (no tag)"),
                "Pin a specific version tag and ideally a sha256 digest: "
                "FROM python:3.12-slim@sha256:<digest>. `latest` moves without your consent.",
                f"FROM {mask(i.value)}",
                [i.start_line],
            ))
        else:
            findings.append(Finding(
                "DS-002", "MEDIUM", WEIGHTS["MEDIUM"],
                "Base image pinned by mutable tag only",
                "Tags can be re-pointed upstream (the Trivy/Docker Hub image incident class). "
                "Pin the digest too: FROM image:tag@sha256:<digest>.",
                f"FROM {mask(i.value)}",
                [i.start_line],
            ))
    return findings


def check_secrets_env(ins: List[Instruction]) -> List[Finding]:
    """DS-003 secrets in ENV/ARG (literal values)."""
    findings = []
    for i in ins:
        if not i.is_cmd("ENV", "ARG"):
            continue
        # split into assignments: ENV A=1 B=2 (legacy `ENV A 1` too)
        chunks = [i.value]
        if _ENV_ASSIGN.match(i.value) is None:
            chunks = [i.value]
        for piece in chunks:
            m = _ENV_ASSIGN.match(piece)
            name = piece.split("=", 1)[0].strip() if m else piece.split(None, 1)[0]
            val = piece.split("=", 1)[1].strip() if m else (piece.split(None, 1)[1] if len(piece.split(None, 1)) > 1 else "")
            if not _SECRET_NAMES.search(name):
                continue
            v = val.strip().strip("\"'")
            if not v:
                continue  # ENV passed through from build args/CI is the correct pattern
            if v.startswith("${") or v.startswith("$"):
                continue  # reference, not a literal
            if _SECRETISH_VALUE.search(v) or (len(v) >= 12 and not re.match(r"^[A-Z0-9_.-]+$", v)):
                findings.append(Finding(
                    "DS-003", "CRITICAL", WEIGHTS["CRITICAL"],
                    f"Secret-looking literal in {i.cmd} (`{name}`)",
                    "Never bake secrets into images - they live in every layer, even if a "
                    "later line removes them. Use runtime secrets (env injection, secret mounts).",
                    f"{i.cmd} {name}={mask(v)}",
                    [i.start_line],
                ))
    return findings


def check_secrets_run(ins: List[Instruction]) -> List[Finding]:
    """DS-005 pipe-to-shell plus DS-004 raw secret material in RUN."""
    findings = []
    for i in ins:
        if not i.is_cmd("RUN"):
            continue
        if _SECRETISH_VALUE.search(i.value):
            findings.append(Finding(
                "DS-004", "CRITICAL", WEIGHTS["CRITICAL"],
                "Hard-coded secret material in RUN",
                "Key/token material appears verbatim in a RUN command and is baked into "
                "image history. Move it to a runtime secret.",
                f"RUN {mask(i.value)}",
                [i.start_line],
            ))
        if _PIPE_SHELL.search(i.value):
            findings.append(Finding(
                "DS-005", "HIGH", WEIGHTS["HIGH"],
                "Remote script piped straight into a shell",
                "`curl ... | sh` executes whatever the server returns, at build time. "
                "Download to a file, verify (checksum/GPG) or COPY from a pinned source, then run.",
                f"RUN {mask(i.value)}",
                [i.start_line],
            ))
    return findings


def check_user(ins: List[Instruction]) -> List[Finding]:
    """DS-006 final stage runs as root."""
    final = _final_stage(ins)
    users = _last_user_lines(ins, final)
    if not users:
        return [Finding(
            "DS-006", "HIGH", WEIGHTS["HIGH"],
            "Final stage never switches away from root",
            "Add a dedicated user and switch to it: RUN useradd -r app && USER app. "
            "A root container that escapes gets root on the host.",
            f"no USER directive in final stage (stage {final})",
            [],
        )]
    last = users[-1]
    if re.match(r"(?i)^(root|0)\b", last.value.strip()):
        return [Finding(
            "DS-006", "HIGH", WEIGHTS["HIGH"],
            "Final stage explicitly runs as root",
            "Run as an unprivileged user; root inside the container multiplies the "
            "blast radius of any escape.",
            f"USER {mask(last.value)}",
            [last.start_line],
        )]
    return []


def check_add_vs_copy(ins: List[Instruction]) -> List[Finding]:
    """DS-007 ADD used where COPY would do."""
    findings = []
    for i in ins:
        if not i.is_cmd("ADD"):
            continue
        # ADD with a URL is legitimate remote-fetch usage; local paths are private
        if not re.match(r"(?i)^(https?|ftp)://", i.value):
            findings.append(Finding(
                "DS-007", "LOW", WEIGHTS["LOW"],
                "ADD used for local content instead of COPY",
                "COPY is the predictable choice; ADD silently unpacks archives and fetches URLs.",
                f"ADD {mask(i.value)}",
                [i.start_line],
            ))
    return findings


def check_sensitive_copy(ins: List[Instruction]) -> List[Finding]:
    """DS-009 sensitive files copied into the image."""
    findings = []
    seen = set()
    for i in ins:
        if not i.is_cmd("COPY", "ADD"):
            continue
        for hit in _SENSITIVE_FILES.finditer(i.raw):
            key = (i.start_line, hit.group(0))
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                "DS-009", "CRITICAL", WEIGHTS["CRITICAL"],
                "Sensitive file copied into the image",
                "Key/credential files end up in image layers and in Docker Hub. Remove the COPY, "
                "mount secrets at runtime, and add the file to .dockerignore.",
                mask(i.raw),
                [i.start_line],
            ))
    return findings


def check_docker_sock(ins: List[Instruction]) -> List[Finding]:
    """DS-010 host Docker socket exposed into the image's habitus."""
    findings = []
    for i in ins:
        if _DOCKER_SOCK.search(i.raw):
            findings.append(Finding(
                "DS-010", "HIGH", WEIGHTS["HIGH"],
                "Host Docker socket referenced",
                "Whoever runs this container owns the host's Docker daemon (root-equivalent). "
                "Almost always a mistake outside of dedicated CI images.",
                mask(i.raw),
                [i.start_line],
            ))
    return findings


def check_sudo(ins: List[Instruction]) -> List[Finding]:
    """DS-011 sudo inside a container."""
    findings = []
    for i in ins:
        if not i.is_cmd("RUN"):
            continue
        if re.search(r"(?<![\w-])sudo\b", i.value):
            findings.append(Finding(
                "DS-011", "MEDIUM", WEIGHTS["MEDIUM"],
                "sudo used inside a build",
                "Builds already run as root; sudo adds a package, audit noise and surprise "
                "caching. Fix permissions explicitly instead.",
                f"RUN {mask(i.value)}",
                [i.start_line],
            ))
    return findings


def check_world_writable(ins: List[Instruction]) -> List[Finding]:
    """DS-012 world-writable permissions."""
    findings = []
    for i in ins:
        if not i.is_cmd("RUN"):
            continue
        if re.search(r"(?i)chmod\s+(?:-R\s+)?(?:[0-7]*7[0-7]*7|a\+w)\b", i.value):
            findings.append(Finding(
                "DS-012", "LOW", WEIGHTS["LOW"],
                "World-writable file permissions",
                "chmod 777-style grants let any process in the container tamper with these "
                "files. Grant only the owner/group that needs it.",
                f"RUN {mask(i.value)}",
                [i.start_line],
            ))
    return findings


def check_apt_hygiene(ins: List[Instruction]) -> List[Finding]:
    """DS-013 apt-get that leaves package lists behind."""
    findings = []
    for i in ins:
        if not i.is_cmd("RUN") or not _APT_INSTALL.search(i.value):
            continue
        if "rm -rf /var/lib/apt/lists" not in i.value.replace("\n", " "):
            findings.append(Finding(
                "DS-013", "LOW", WEIGHTS["LOW"],
                "apt-get without list cleanup",
                "Clean apt lists in the same RUN layer: "
                "&& rm -rf /var/lib/apt/lists/* (smaller image, fewer stale mirrors).",
                f"RUN {mask(i.value)}",
                [i.start_line],
            ))
    return findings


def check_healthcheck(ins: List[Instruction]) -> List[Finding]:
    """DS-014 EXPOSEd service without a HEALTHCHECK."""
    exposed = any(i.is_cmd("EXPOSE") for i in ins)
    has_hc = any(i.is_cmd("HEALTHCHECK") for i in ins)
    if exposed and not has_hc:
        expose_lines = [i.start_line for i in ins if i.is_cmd("EXPOSE")]
        return [Finding(
            "DS-014", "LOW", WEIGHTS["LOW"],
            "Service image without HEALTHCHECK",
            "Add HEALTHCHECK so orchestrators can tell a live container from a zombie "
            "(e.g. HEALTHCHECK CMD curl -f http://localhost/health || exit 1).",
            "EXPOSE without HEALTHCHECK",
            expose_lines,
        )]
    return []


def check_dockerignore(ins: List[Instruction], dockerignore_exists: Optional[bool]) -> List[Finding]:
    """DS-008 build context missing .dockerignore (checker flag: None = unknown)."""
    if dockerignore_exists is None or dockerignore_exists:
        return []
    return [Finding(
        "DS-008", "MEDIUM", WEIGHTS["MEDIUM"],
        "No .dockerignore next to the Dockerfile",
        "Without .dockerignore the build context ships .git, .env, node_modules and any "
        "credential file straight into the daemon (and into any COPY . layer). "
        "Commit a .dockerignore at least containing .git, .env, *.pem, id_rsa, node_modules.",
        "missing .dockerignore in context directory",
        [],
    )]


ALL_RULES = (
    ("DS-001/002", check_from_pinning),
    ("DS-003", check_secrets_env),
    ("DS-004/005", check_secrets_run),
    ("DS-006", check_user),
    ("DS-007", check_add_vs_copy),
    ("DS-008", None),  # invoked explicitly with context
    ("DS-009", check_sensitive_copy),
    ("DS-010", check_docker_sock),
    ("DS-011", check_sudo),
    ("DS-012", check_world_writable),
    ("DS-013", check_apt_hygiene),
    ("DS-014", check_healthcheck),
)


def run_all_rules(instructions: List[Instruction], dockerignore_exists: Optional[bool] = None) -> List[Finding]:
    """Run every rule; order = parse order for stable output."""
    findings: List[Finding] = []
    findings += check_from_pinning(instructions)
    findings += check_secrets_env(instructions)
    findings += check_secrets_run(instructions)
    findings += check_user(instructions)
    findings += check_add_vs_copy(instructions)
    if dockerignore_exists is not None:
        findings += check_dockerignore(instructions, dockerignore_exists)
    findings += check_sensitive_copy(instructions)
    findings += check_docker_sock(instructions)
    findings += check_sudo(instructions)
    findings += check_world_writable(instructions)
    findings += check_apt_hygiene(instructions)
    findings += check_healthcheck(instructions)
    # stable, readable output: severity desc, then first line
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (sev_rank[f.severity], f.lines[0] if f.lines else 0, f.rule_id))
    return findings
