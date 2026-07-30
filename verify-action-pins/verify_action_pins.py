#!/usr/bin/env python3
"""Verify that every third-party `uses:` reference in a workflow is pinned to a
SHA that a semver release tag actually points at, and that the release behind
that tag has been published for at least a minimum age.

Why this exists
---------------
Renovate can enforce a minimum release age only when the update it proposes
carries a release timestamp. A bare digest -- a 40-character SHA -- has none:
the `github-tags` datasource attaches no timestamp to it, so Renovate cannot
tell a commit published a year ago from one pushed a minute ago. That gap is
exactly the tag-hijack shape SHA pinning is supposed to defend against: move
`v4` onto a malicious commit, and anything that resolves `v4` adopts it.

The check here closes the gap from outside Renovate, using two facts that a
SHA alone does not give you:

1. **Provenance.** The pinned SHA must be the exact target of a semver tag
   (`vX.Y.Z`) in the upstream repository. A commit that no release tag points
   at is never something we intend to run, whatever its comment claims.
2. **Age.** The release for that tag must have been published at least
   `--min-age-days` ago, measured by the release's `published_at`.

`published_at` is assigned by GitHub when the release is published and is not
settable through the REST API, which is why it is the anchor rather than commit
metadata: `committer.date` is just a string in the commit object and
`GIT_COMMITTER_DATE` lets an attacker backdate a freshly pushed commit to any
date they like. An attacker who can move a tag still cannot retroactively have
published a release last week.

The check fails closed. No tag match, no release, no timestamp, or an API error
all count as failures -- a check that silently passes when it cannot see the
data is worse than no check, because it converts an unknown into a green tick.
Genuine exceptions (an action that ships tags without releases, say) go in the
allowlist file, where they are explicit and reviewable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

API = "https://api.github.com"

# `uses: owner/repo[/path]@ref  # comment`. Anchored on the `uses:` key so that
# `with:` values or prose mentioning an action are not picked up.
USES = re.compile(
    r"^\s*(?:-\s*)?uses:\s*['\"]?(?P<ref>[^\s'\"#]+)['\"]?"
    r"(?:\s*#\s*(?P<comment>.*?))?\s*$"
)
SHA = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG = re.compile(r"^v?\d+\.\d+\.\d+$")

# Reusable workflows and actions living in the caller's own repository are
# resolved by git ref, not fetched from a third party, so pinning them to a SHA
# would gain nothing and break `uses: ./.github/actions/foo` entirely.
LOCAL_PREFIXES = ("./", "../")


@dataclass
class Finding:
    """One `uses:` reference and the verdict reached for it."""

    file: str
    line: int
    ref: str
    status: str  # "pass" | "fail" | "skip"
    detail: str
    tags: list[str] = field(default_factory=list)


class GitHub:
    """Minimal GitHub REST client with per-endpoint memoisation.

    A workflow tree references the same handful of actions dozens of times;
    caching keeps a repo-wide scan to a few requests per action instead of one
    per `uses:` line.
    """

    def __init__(self, token: str | None) -> None:
        self.token = token
        self._cache: dict[str, object] = {}

    def get(self, path: str) -> object:
        if path in self._cache:
            return self._cache[path]
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "workos-verify-action-pins",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(f"{API}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.load(resp)
        except urllib.error.HTTPError as exc:
            body = {"_error": f"HTTP {exc.code}"}
        except Exception as exc:  # network/DNS/timeout -- still fail closed
            body = {"_error": str(exc)}
        self._cache[path] = body
        return body

    def semver_tags_at(self, repo: str, sha: str) -> list[str]:
        """Semver tag names in `repo` whose target commit is `sha`.

        Annotated tags point at a tag object rather than a commit, so those are
        peeled one level to compare against the commit SHA a workflow pins.
        """
        refs = self.get(f"/repos/{repo}/git/matching-refs/tags/")
        if not isinstance(refs, list):
            return []
        out = []
        for ref in refs:
            name = ref.get("ref", "").removeprefix("refs/tags/")
            if not SEMVER_TAG.match(name):
                continue
            obj = ref.get("object", {})
            target = obj.get("sha")
            if obj.get("type") == "tag":
                peeled = self.get(f"/repos/{repo}/git/tags/{target}")
                if isinstance(peeled, dict):
                    target = peeled.get("object", {}).get("sha", target)
            if target == sha:
                out.append(name)
        return out

    def release_published_at(self, repo: str, tag: str) -> tuple[dt.datetime | None, str]:
        rel = self.get(f"/repos/{repo}/releases/tags/{tag}")
        if not isinstance(rel, dict) or "_error" in rel:
            err = rel.get("_error", "unknown error") if isinstance(rel, dict) else "bad response"
            return None, f"no release for {tag} ({err})"
        stamp = rel.get("published_at")
        if not stamp:
            return None, f"release {tag} has no published_at"
        return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")), ""


def load_allowlist(path: str) -> dict[str, str]:
    """Read `owner/repo: reason` lines from the allowlist file.

    Deliberately parsed by hand rather than with PyYAML so the action needs no
    dependencies beyond the Python that every GitHub runner already ships.
    Comments and blank lines are ignored; anything else must be `key: reason`.
    """
    allow: dict[str, str] = {}
    if not path or not os.path.exists(path):
        return allow
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            key, _, reason = line.partition(":")
            allow[key.strip()] = reason.strip()
    return allow


def workflow_files(paths: list[str]) -> list[str]:
    found = []
    for root in paths:
        if os.path.isfile(root):
            found.append(root)
            continue
        for dirpath, _, names in os.walk(root):
            for name in names:
                if name.endswith((".yml", ".yaml")):
                    found.append(os.path.join(dirpath, name))
    return sorted(found)


def changed_files(base: str) -> list[str]:
    """Workflow files touched relative to `base`, for PR-scoped runs."""
    merge_base = subprocess.run(
        ["git", "merge-base", "HEAD", base],
        capture_output=True, text=True, check=False,
    ).stdout.strip() or base
    diff = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=d", merge_base, "HEAD"],
        capture_output=True, text=True, check=False,
    ).stdout.split()
    return [f for f in diff if f.endswith((".yml", ".yaml")) and os.path.exists(f)]


def verify_ref(gh: GitHub, ref: str, min_age: dt.timedelta, allow: dict[str, str],
               now: dt.datetime, internal_owner: str | None = None) -> tuple[str, str, list[str]]:
    """Classify a single `owner/repo[/path]@ref` reference."""
    target, _, pin = ref.partition("@")
    if ref.startswith(LOCAL_PREFIXES) or ref.startswith("docker://") or not pin:
        return "skip", "local or non-action reference", []

    # Sub-path actions (`actions/cache/restore`) live in their owner's repo, so
    # tags and releases must be looked up on `owner/repo`.
    parts = target.split("/")
    if len(parts) < 2:
        return "skip", "unrecognised reference", []
    repo = "/".join(parts[:2])

    # First-party actions and reusable workflows are covered by this same check
    # in the repository that owns them, and they are conventionally referenced
    # by branch (`@main`) so a fix propagates without a bump everywhere. Demanding
    # a SHA here would relocate the trust decision, not strengthen it.
    if internal_owner and parts[0].lower() == internal_owner.lower():
        return "skip", f"first-party ({internal_owner})", []

    if repo in allow:
        return "skip", f"allowlisted: {allow[repo] or 'no reason given'}", []
    if not SHA.match(pin):
        return "fail", f"not SHA-pinned (pinned to {pin!r})", []

    tags = gh.semver_tags_at(repo, pin)
    if not tags:
        return "fail", "pinned SHA is not the target of any vX.Y.Z tag", []

    # Several tags can share a commit (v4.4.0 and v4 both pointing at it). The
    # pin is acceptable if any of them is backed by a sufficiently old release.
    problems = []
    for tag in sorted(tags):
        published, err = gh.release_published_at(repo, tag)
        if published is None:
            problems.append(err)
            continue
        age = now - published
        if age >= min_age:
            return "pass", f"{tag} published {age.days}d ago", tags
        problems.append(f"{tag} published {age.days}d ago, under minimum")
    return "fail", "; ".join(problems), tags


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", default=[".github"],
                    help="workflow/action files or directories to scan")
    ap.add_argument("--base", help="only check workflow files changed vs this ref")
    ap.add_argument("--min-age-days", type=int, default=7)
    ap.add_argument("--allowlist", default=".github/action-pin-allowlist.yml")
    ap.add_argument("--internal-owner", default=os.environ.get("GITHUB_REPOSITORY_OWNER"),
                    help="owner whose own actions are first-party and skipped")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    args = ap.parse_args()

    files = changed_files(args.base) if args.base else workflow_files(args.paths or [".github"])
    gh = GitHub(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    allow = load_allowlist(args.allowlist)
    min_age = dt.timedelta(days=args.min_age_days)
    now = dt.datetime.now(dt.timezone.utc)

    findings: list[Finding] = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                m = USES.match(line)
                if not m:
                    continue
                ref = m.group("ref")
                status, detail, tags = verify_ref(
                    gh, ref, min_age, allow, now, args.internal_owner
                )
                findings.append(Finding(path, lineno, ref, status, detail, tags))

    failures = [f for f in findings if f.status == "fail"]
    for f in findings:
        if f.status != "pass":
            print(f"{f.status.upper():4s} {f.file}:{f.line} {f.ref} -- {f.detail}")
    print(
        f"\n{len(findings)} references checked in {len(files)} file(s): "
        f"{sum(1 for f in findings if f.status == 'pass')} pass, "
        f"{len(failures)} fail, "
        f"{sum(1 for f in findings if f.status == 'skip')} skipped"
    )

    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(f"### Action pin verification (min age {args.min_age_days}d)\n\n")
            if not failures:
                fh.write(f"All {len(findings)} references verified.\n")
            else:
                fh.write("| file:line | reference | problem |\n|---|---|---|\n")
                for f in failures:
                    fh.write(f"| `{f.file}:{f.line}` | `{f.ref}` | {f.detail} |\n")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
