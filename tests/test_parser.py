"""Parser tests: continuations, comments, stages, error handling."""

import unittest

from dockseal.parser import DockerfileParseError, parse_dockerfile


class TestParse(unittest.TestCase):
    def test_simple(self):
        ins = parse_dockerfile("FROM alpine:3.20\nRUN echo hi\n")
        self.assertEqual([i.cmd for i in ins], ["FROM", "RUN"])
        self.assertEqual(ins[1].value, "echo hi")

    def test_continuation_joins(self):
        text = "RUN apt-get update && \\\n    apt-get install -y curl \\\n    && rm -rf /var/lib/apt/lists/*\n"
        ins = parse_dockerfile(text)
        self.assertEqual(len(ins), 1)
        self.assertIn("apt-get install", ins[0].value)
        self.assertIn("/var/lib/apt", ins[0].value)
        self.assertEqual((ins[0].start_line, ins[0].end_line), (1, 3))

    def test_line_numbers_account_for_comments_and_blanks(self):
        text = "# a comment\n\nFROM python:3.12\n\nCOPY . /app\n"
        ins = parse_dockerfile(text)
        self.assertEqual(ins[0].start_line, 3)
        self.assertEqual(ins[1].start_line, 5)

    def test_inline_comment_after_instruction_is_ignored(self):
        ins = parse_dockerfile("FROM alpine:3.20 # pinned\n")
        self.assertEqual(ins[0].value, "alpine:3.20")
        # the appended text must not have leaked into the value
        self.assertNotIn("#", ins[0].value)

    def test_hash_inside_quotes_is_not_comment(self):
        ins = parse_dockerfile('RUN echo "a # b"\n')
        self.assertEqual(ins[0].value, 'echo "a # b"')

    def test_stages_increment(self):
        text = ("FROM golang:1.22 AS builder\n"
                "RUN go build\n"
                "FROM golang:1.22\n"
                "COPY --from=builder /app /app\n")
        ins = parse_dockerfile(text)
        self.assertEqual([i.stage for i in ins], [0, 0, 1, 1])

    def test_stage_alias_stripped_from_value_is_caller_concern(self):
        ins = parse_dockerfile("FROM alpine:3.20 AS base\nRUN echo hi\n")
        self.assertEqual(ins[0].value, "alpine:3.20 AS base")

    def test_empty_input_raises(self):
        with self.assertRaises(DockerfileParseError):
            parse_dockerfile("\n\n# only a comment\n")

    def test_whitespace_only_value(self):
        ins = parse_dockerfile("WORKDIR /app\n")
        self.assertEqual(ins[0].cmd, "WORKDIR")


if __name__ == "__main__":
    unittest.main()
