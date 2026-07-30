#!/usr/bin/env python3
"""Tests for verify_action_pins, run against a stub GitHub client.

The verdicts here are the security properties of the check, so they are worth
asserting without a network round trip: the live API is rate-limited, and a test
suite that only passes when GitHub is reachable and generous stops being run.
"""

from __future__ import annotations

import datetime as dt
import unittest

from verify_action_pins import USES, GitHub, verify_ref

NOW = dt.datetime(2026, 7, 30, tzinfo=dt.timezone.utc)
MIN_AGE = dt.timedelta(days=7)
OLD = "2026-01-01T00:00:00Z"      # comfortably aged
FRESH = "2026-07-29T00:00:00Z"    # one day old
AGED_SHA = "a" * 40
FRESH_SHA = "b" * 40
UNTAGGED_SHA = "c" * 40


class StubGitHub(GitHub):
    """GitHub client backed by a fixed dict of API responses."""

    def __init__(self, responses: dict[str, object]) -> None:
        super().__init__(token=None)
        self.responses = responses
        self.requested: list[str] = []

    def get(self, path: str) -> object:
        self.requested.append(path)
        return self.responses.get(path, {"_error": "HTTP 404"})


def responses() -> dict[str, object]:
    return {
        "/repos/o/r/git/ref/tags/v1.2.3": {"object": {"type": "commit", "sha": AGED_SHA}},
        "/repos/o/r/git/ref/tags/v9.9.9": {"object": {"type": "commit", "sha": FRESH_SHA}},
        "/repos/o/r/releases/tags/v1.2.3": {"published_at": OLD},
        "/repos/o/r/releases/tags/v9.9.9": {"published_at": FRESH},
        "/repos/o/r/tags?per_page=100&page=1": [
            {"name": "v1.2.3", "commit": {"sha": AGED_SHA}},
            {"name": "v9.9.9", "commit": {"sha": FRESH_SHA}},
        ],
    }


class VerifyRefTest(unittest.TestCase):
    def verify(self, ref: str, comment: str | None = None, allow=None, owner=None,
               extra: dict[str, object] | None = None):
        gh = StubGitHub({**responses(), **(extra or {})})
        self.gh = gh
        return verify_ref(gh, ref, MIN_AGE, allow or {}, NOW, owner, comment)

    def test_aged_release_passes(self):
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", "v1.2.3")
        self.assertEqual(status, "pass")
        self.assertIn("v1.2.3", detail)

    def test_release_under_minimum_age_fails(self):
        status, detail, _ = self.verify(f"o/r@{FRESH_SHA}", "v9.9.9")
        self.assertEqual(status, "fail")
        self.assertIn("under minimum", detail)

    def test_sha_not_on_any_semver_tag_fails(self):
        status, detail, _ = self.verify(f"o/r@{UNTAGGED_SHA}", "v1.2.3")
        self.assertEqual(status, "fail")
        self.assertIn("not the target", detail)

    def test_lying_comment_is_not_believed(self):
        """A comment claiming an aged tag cannot launder a SHA that tag doesn't point at."""
        status, _, _ = self.verify(f"o/r@{FRESH_SHA}", "v1.2.3")
        self.assertEqual(status, "fail")

    def test_comment_is_only_a_hint_not_a_requirement(self):
        """No comment (or a stale one) still resolves via the tag list."""
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", None)
        self.assertEqual(status, "pass")
        self.assertIn("v1.2.3", detail)

    def test_unpinned_tag_fails(self):
        status, detail, _ = self.verify("o/r@v1.2.3")
        self.assertEqual(status, "fail")
        self.assertIn("not SHA-pinned", detail)

    def test_missing_release_fails_closed(self):
        gh_responses = {"/repos/o/r/releases/tags/v1.2.3": {"_error": "HTTP 404"}}
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", "v1.2.3", extra=gh_responses)
        self.assertEqual(status, "fail")
        self.assertIn("no release", detail)

    def test_api_error_fails_closed(self):
        gh = StubGitHub({})
        status, _, _ = verify_ref(gh, f"o/r@{AGED_SHA}", MIN_AGE, {}, NOW, None, "v1.2.3")
        self.assertEqual(status, "fail")

    def test_allowlist_skips(self):
        status, detail, _ = self.verify(f"o/r@{UNTAGGED_SHA}", allow={"o/r": "no releases"})
        self.assertEqual(status, "skip")
        self.assertIn("no releases", detail)

    def test_first_party_skipped(self):
        status, _, _ = self.verify("workos/actions/.github/workflows/x.yml@main", owner="workos")
        self.assertEqual(status, "skip")

    def test_local_reference_skipped(self):
        status, _, _ = self.verify("./.github/actions/build")
        self.assertEqual(status, "skip")

    def test_subpath_action_resolves_against_owner_repo(self):
        status, _, _ = self.verify(f"o/r/sub/dir@{AGED_SHA}", "v1.2.3")
        self.assertEqual(status, "pass")

    def test_annotated_tag_is_peeled(self):
        extra = {
            "/repos/o/r/git/ref/tags/v1.2.3": {"object": {"type": "tag", "sha": "d" * 40}},
            "/repos/o/r/git/tags/" + "d" * 40: {"object": {"sha": AGED_SHA}},
        }
        status, _, _ = self.verify(f"o/r@{AGED_SHA}", "v1.2.3", extra=extra)
        self.assertEqual(status, "pass")

    def test_verified_comment_avoids_walking_the_tag_list(self):
        self.verify(f"o/r@{AGED_SHA}", "v1.2.3")
        self.assertNotIn("/repos/o/r/tags?per_page=100&page=1", self.gh.requested)


class UsesPatternTest(unittest.TestCase):
    def parse(self, line: str):
        m = USES.match(line)
        return (m.group("ref"), m.group("comment")) if m else None

    def test_forms_of_uses_line(self):
        cases = [
            ("      - uses: o/r@sha # v1.2.3\n", ("o/r@sha", "v1.2.3")),
            ("        uses: 'o/r@sha'  # v1.2.3 (comment)\n", ("o/r@sha", "v1.2.3 (comment)")),
            ("      - uses: o/r@sha\n", ("o/r@sha", None)),
            ("      - uses: docker://alpine:3\n", ("docker://alpine:3", None)),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(self.parse(line), expected)

    def test_non_uses_lines_ignored(self):
        for line in ("        with:\n", "        # uses: o/r@v1\n", "          image: o/r@sha\n"):
            with self.subTest(line=line):
                self.assertIsNone(self.parse(line))


if __name__ == "__main__":
    unittest.main()
