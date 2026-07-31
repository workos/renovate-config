#!/usr/bin/env python3
"""Tests for verify_action_pins, run against a stub GitHub client.

The verdicts here are the security properties of the check, so they are worth
asserting without a network round trip: the live API is rate-limited, and a test
suite that only passes when GitHub is reachable and generous stops being run.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import tempfile
import unittest
import unittest.mock

from verify_action_pins import (
    GitHub,
    Unverifiable,
    changed_files,
    uses_in_file,
    verify_ref,
)

NOW = dt.datetime(2026, 7, 30, tzinfo=dt.timezone.utc)
MIN_AGE = dt.timedelta(days=7)
OLD = "2026-01-01T00:00:00Z"        # comfortably aged release
FRESH = "2026-07-29T00:00:00Z"      # release one day old
OLD_COMMIT = "2025-12-31T00:00:00Z"  # commit that predates the aged release
NEW_COMMIT = "2026-07-29T12:00:00Z"  # commit created long after it
AGED_SHA = "a" * 40
FRESH_SHA = "b" * 40
UNTAGGED_SHA = "c" * 40
MOVED_SHA = "d" * 40


class StubGitHub(GitHub):
    """GitHub client backed by fixed API responses and a fixed tag namespace."""

    def __init__(self, responses: dict[str, object],
                 tags: dict[str, str] | None = None,
                 tag_error: str | None = None) -> None:
        super().__init__(token=None)
        self.responses = responses
        self.tag_map = tags if tags is not None else default_tags()
        self.tag_error = tag_error
        self.requested: list[str] = []

    def tags(self, repo: str) -> dict[str, str]:
        if self.tag_error:
            raise Unverifiable(self.tag_error)
        return self.tag_map

    def get(self, path: str) -> object:
        self.requested.append(path)
        return self.responses.get(path, {"_error": "HTTP 404"})


def default_tags() -> dict[str, str]:
    return {
        "v1.2.3": AGED_SHA,
        "v1.2": AGED_SHA,        # not full semver: never an anchor
        "v9.9.9": FRESH_SHA,
        "v2.0.0": MOVED_SHA,     # aged release, but commit is newer than it
    }


def responses() -> dict[str, object]:
    return {
        "/repos/o/r/releases/tags/v1.2.3": {"published_at": OLD},
        "/repos/o/r/releases/tags/v9.9.9": {"published_at": FRESH},
        "/repos/o/r/releases/tags/v2.0.0": {"published_at": OLD},
        f"/repos/o/r/commits/{AGED_SHA}": {"commit": {
            "author": {"date": OLD_COMMIT}, "committer": {"date": OLD_COMMIT}}},
        f"/repos/o/r/commits/{MOVED_SHA}": {"commit": {
            "author": {"date": OLD_COMMIT}, "committer": {"date": NEW_COMMIT}}},
        f"/repos/o/r/commits/{FRESH_SHA}": {"commit": {
            "author": {"date": NEW_COMMIT}, "committer": {"date": NEW_COMMIT}}},
    }


class VerifyRefTest(unittest.TestCase):
    def verify(self, ref: str, allow=None, owner=None, require_immutable=False,
               extra: dict[str, object] | None = None,
               tags: dict[str, str] | None = None, tag_error: str | None = None):
        gh = StubGitHub({**responses(), **(extra or {})}, tags, tag_error)
        self.gh = gh
        return verify_ref(gh, ref, MIN_AGE, allow or {}, NOW, owner, require_immutable)

    def test_aged_release_passes(self):
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}")
        self.assertEqual(status, "pass")
        self.assertIn("v1.2.3", detail)

    def test_release_under_minimum_age_fails(self):
        status, detail, _ = self.verify(f"o/r@{FRESH_SHA}")
        self.assertEqual(status, "fail")
        self.assertIn("under minimum", detail)

    def test_sha_not_on_any_semver_tag_fails(self):
        status, detail, _ = self.verify(f"o/r@{UNTAGGED_SHA}")
        self.assertEqual(status, "fail")
        self.assertIn("not the target", detail)

    def test_partial_version_tag_is_not_an_anchor(self):
        """`v1.2` shares the commit but only `vX.Y.Z` may vouch for a pin."""
        status, _, tags = self.verify(f"o/r@{AGED_SHA}")
        self.assertEqual(status, "pass")
        self.assertNotIn("v1.2", tags)

    def test_moved_tag_cannot_reuse_an_old_release(self):
        """An old release does not vouch for a commit created after it."""
        status, detail, _ = self.verify(f"o/r@{MOVED_SHA}")
        self.assertEqual(status, "fail")
        self.assertIn("appears to have been moved", detail)

    def test_immutable_release_needs_no_commit_date(self):
        extra = {"/repos/o/r/releases/tags/v2.0.0": {"published_at": OLD, "immutable": True}}
        status, detail, _ = self.verify(f"o/r@{MOVED_SHA}", extra=extra)
        self.assertEqual(status, "pass")
        self.assertIn("immutable release", detail)
        self.assertNotIn(f"/repos/o/r/commits/{MOVED_SHA}", self.gh.requested)

    def test_require_immutable_rejects_a_mutable_tag(self):
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", require_immutable=True)
        self.assertEqual(status, "fail")
        self.assertIn("not an immutable release", detail)

    def test_missing_commit_metadata_fails_closed(self):
        extra = {f"/repos/o/r/commits/{AGED_SHA}": {"_error": "HTTP 500"}}
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", extra=extra)
        self.assertEqual(status, "fail")
        self.assertIn("cannot read commit", detail)

    def test_sibling_tag_can_vouch_when_the_first_has_no_release(self):
        """One tag lacking a release must not condemn a commit another vouches for."""
        tags = {"1.2.3": AGED_SHA, "v1.2.3": AGED_SHA}
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", tags=tags)
        self.assertEqual(status, "pass")
        self.assertIn("v1.2.3", detail)

    def test_unpinned_tag_fails(self):
        status, detail, _ = self.verify("o/r@v1.2.3")
        self.assertEqual(status, "fail")
        self.assertIn("not SHA-pinned", detail)

    def test_missing_release_fails_closed(self):
        extra = {"/repos/o/r/releases/tags/v1.2.3": {"_error": "HTTP 404"}}
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", extra=extra)
        self.assertEqual(status, "fail")
        self.assertIn("no release", detail)

    def test_tag_listing_failure_fails_closed(self):
        status, detail, _ = self.verify(f"o/r@{AGED_SHA}", tag_error="cannot list tags of o/r")
        self.assertEqual(status, "fail")
        self.assertIn("cannot list tags", detail)

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

    def test_container_step_must_be_digest_pinned(self):
        """A `docker://` step runs third-party code and a tag can be retargeted."""
        digest = "sha256:" + "a" * 64
        status, detail, _ = self.verify(f"docker://ghcr.io/o/img@{digest}")
        self.assertEqual(status, "pass")
        self.assertIn("digest", detail)

        status, detail, _ = self.verify("docker://ghcr.io/o/img:3")
        self.assertEqual(status, "fail")
        self.assertIn("not digest-pinned", detail)

        status, detail, _ = self.verify(
            "docker://ghcr.io/o/img:3", allow={"ghcr.io/o/img": "built by us"})
        self.assertEqual(status, "skip")
        self.assertIn("built by us", detail)

    def test_subpath_action_resolves_against_owner_repo(self):
        status, _, _ = self.verify(f"o/r/sub/dir@{AGED_SHA}")
        self.assertEqual(status, "pass")


class TagListingTest(unittest.TestCase):
    """`GitHub.tags` reads the whole tag namespace, peeling annotated tags."""

    def test_ls_remote_output_is_peeled_and_complete(self):
        gh = GitHub(token=None)
        annotated = "e" * 40
        out = (
            f"{annotated}\trefs/tags/v1.0.0\n"
            f"{AGED_SHA}\trefs/tags/v1.0.0^{{}}\n"
            f"{FRESH_SHA}\trefs/tags/v2.0.0\n"
            "deadbeef\trefs/heads/main\n"
        )
        with unittest.mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, out, "")
            tags = gh.tags("o/r")
        self.assertEqual(tags, {"v1.0.0": AGED_SHA, "v2.0.0": FRESH_SHA})

    def test_git_failure_is_unverifiable(self):
        gh = GitHub(token=None)
        with unittest.mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 128, "", "boom")
            with self.assertRaises(Unverifiable):
                gh.tags("o/r")


class ChangedFilesTest(unittest.TestCase):
    """A PR-scoped run must not treat "git failed" as "nothing to check"."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.cwd = os.getcwd()
        self.addCleanup(os.chdir, self.cwd)
        os.chdir(self.dir.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "Test")
        os.makedirs(".github/workflows")
        self.write(".github/workflows/ci.yml", "on: push\n")
        self.write("other.yml", "unrelated: true\n")
        self.git("add", ".github/workflows/ci.yml", "other.yml")
        self.git("commit", "-qm", "Add workflows")
        self.git("checkout", "-qb", "feature")
        self.write(".github/workflows/ci.yml", "on: pull_request\n")
        self.write("other.yml", "unrelated: false\n")
        self.git("commit", "-qam", "Change workflows")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], check=True, capture_output=True)

    def write(self, path: str, body: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)

    def test_unresolvable_base_is_unverifiable_not_empty(self):
        with self.assertRaises(Unverifiable):
            changed_files("origin/does-not-exist", [".github"])

    def test_changed_files_are_restricted_to_requested_paths(self):
        self.assertEqual(
            changed_files("main", [".github"]),
            [".github/workflows/ci.yml"],
        )
        self.assertIn("other.yml", changed_files("main", ["."]))

    def test_path_with_a_space_is_still_scanned(self):
        """git quotes such a path; reading it as words loses the whole file."""
        spaced = ".github/workflows/build and test.yml"
        self.write(spaced, "on: push\n")
        self.git("add", spaced)
        self.git("commit", "-qm", "Add a workflow whose name has a space")
        self.assertIn(spaced, changed_files("main", [".github"]))


class UsesScanTest(unittest.TestCase):
    """Every YAML form the scanner misses is an unchecked executable action."""

    def scan(self, body: str) -> list[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(body)
            self.addCleanup(os.unlink, fh.name)
        return [ref for _, ref in uses_in_file(fh.name)]

    def test_every_step_syntax_is_scanned(self):
        """Actions accepts all of these; a scanner that reads only the common
        block form vouches for the rest without looking at them."""
        cases = [
            ("steps:\n  - uses: o/r@sha # v1.2.3\n", ["o/r@sha"]),
            ("steps:\n  - uses: 'o/r@sha'  # v1.2.3\n", ["o/r@sha"]),
            ("steps:\n  - uses: docker://alpine:3\n", ["docker://alpine:3"]),
            ("steps:\n  - 'uses': o/r@main\n", ["o/r@main"]),
            ("steps:\n  - {uses: o/r@main}\n", ["o/r@main"]),
            ("steps: [{uses: a/b@main}, {uses: c/d@main}]\n", ["a/b@main", "c/d@main"]),
            # Value on the following line, folded, and via an anchor.
            ("steps:\n  - uses:\n      o/r@main\n", ["o/r@main"]),
            ("steps:\n  - uses: >-\n      o/r@main\n", ["o/r@main"]),
            ("x: &s {uses: o/r@main}\nsteps:\n  - *s\n", ["o/r@main"]),
            # Nested wherever it appears: a composite action's own steps.
            ("runs:\n  using: composite\n  steps:\n    - uses: o/r@main\n", ["o/r@main"]),
        ]
        for body, expected in cases:
            with self.subTest(body=body):
                self.assertEqual(self.scan(body), expected)

    def test_non_uses_keys_ignored(self):
        body = (
            "steps:\n"
            "  - with:\n"
            "      image: o/r@sha\n"
            "  # - uses: o/r@commented-out\n"
            "  - reuses: o/r@sha\n"
        )
        self.assertEqual(self.scan(body), [])

    def test_unparseable_file_is_unverifiable(self):
        """A file the scanner cannot read is red, not empty."""
        with self.assertRaises(Unverifiable):
            self.scan("steps:\n  - uses: o/r@sha\n   bad: [unclosed\n")

    def test_line_numbers_locate_the_reference(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write("steps:\n  - run: true\n  - uses: o/r@sha\n")
            self.addCleanup(os.unlink, fh.name)
        self.assertEqual(uses_in_file(fh.name), [(3, "o/r@sha")])


if __name__ == "__main__":
    unittest.main()
