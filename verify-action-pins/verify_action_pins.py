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

The check here closes the gap from outside Renovate, using facts that a SHA
alone does not give you:

1. **Provenance.** The pinned SHA must be the exact target of a semver tag
   (`vX.Y.Z`) in the upstream repository. A commit that no release tag points
   at is never something we intend to run, whatever its comment claims.
2. **Age.** The release for that tag must have been published at least
   `--min-age-days` ago, measured by the release's `published_at`.
3. **Binding.** The release must plausibly be *about* the pinned commit. A
   semver tag is still a mutable ref: moving `v4.3.1` onto a fresh commit
   satisfies (1) and inherits the old release's `published_at`, so age alone
   would pass a commit created minutes ago. Two signals close that:

   * `immutable` on the release. GitHub's immutable releases (GA October 2025)
     make the tag unmovable, so the timestamp genuinely describes the commit.
     This is proof, and `--require-immutable` insists on it.
   * Otherwise, the commit must not be newer than the release that supposedly
     shipped it. A released commit predates its release; a commit that appears
     *after* the release it claims means the tag moved. This is a consistency
     check rather than proof -- `GIT_COMMITTER_DATE` lets an attacker backdate
     a pushed commit -- so it raises the bar without being airtight. Detecting
     a moved tag independently of upstream metadata needs a first-seen ledger
     of `(action, tag) -> sha`, which is deliberately left to a later change.

`published_at` is the anchor rather than commit metadata because it is assigned
by GitHub when the release is published and is not settable through the REST
API, whereas `committer.date` is just a string in the commit object.

The check fails closed. No tag match, no release, no timestamp, no commit
metadata, an API error, or a git failure that leaves it unsure which files to
inspect all count as failures -- a check that silently passes when it cannot see
the data is worse than no check, because it converts an unknown into a green
tick. Genuine exceptions (an action that ships tags without releases, say) go in
the allowlist file, where they are explicit and reviewable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

import yaml

API = "https://api.github.com"

SHA = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG = re.compile(r"^v?\d+\.\d+\.\d+$")

# Reusable workflows and actions living in the caller's own repository are
# resolved by git ref, not fetched from a third party, so pinning them to a SHA
# would gain nothing and break `uses: ./.github/actions/foo` entirely.
LOCAL_PREFIXES = ("./", "../")

# A commit can carry a timestamp slightly after the release that ships it (clock
# skew, or a release published from a tag created moments earlier), so the
# "commit is not newer than its release" comparison needs a little slack.
CLOCK_SKEW = dt.timedelta(hours=1)


class Unverifiable(Exception):
    """Raised when the data needed for a verdict cannot be obtained.

    Distinct from a failed verdict: it means the check could not see enough to
    judge, which must still surface as red rather than as a pass.
    """


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
        self._tags: dict[str, dict[str, str]] = {}

    def get(self, path: str) -> object:
        """GET an API path, retrying transient failures.

        403 and 429 are GitHub's rate-limit responses and 5xx are transient; a
        check that failed on those would flap red for reasons unrelated to the
        pins it is verifying, and a flapping required check gets disabled. Only
        a persistent failure is surfaced to the caller, which then fails closed.
        """
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
        body: object = {"_error": "not attempted"}
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = json.load(resp)
                break
            except urllib.error.HTTPError as exc:
                body = {"_error": f"HTTP {exc.code}"}
                if not (exc.code in (403, 429) or exc.code >= 500):
                    break
                delay = self._retry_after(exc, attempt)
            except Exception as exc:  # network/DNS/timeout
                body = {"_error": str(exc)}
                delay = 2 ** attempt
            if attempt < 3:
                time.sleep(delay)
        self._cache[path] = body
        return body

    @staticmethod
    def _retry_after(exc: urllib.error.HTTPError, attempt: int) -> float:
        """Seconds to wait, preferring GitHub's own guidance to guesswork."""
        for header in ("Retry-After", "X-RateLimit-Reset"):
            value = exc.headers.get(header)
            if not value:
                continue
            try:
                seconds = float(value)
            except ValueError:
                continue
            if header == "X-RateLimit-Reset":
                seconds -= time.time()
            # A primary-limit reset can be an hour out; waiting that long inside
            # a check is worse than failing it, so cap and let the retry decide.
            return max(1.0, min(seconds, 60.0))
        return float(2 ** attempt)

    def tags(self, repo: str) -> dict[str, str]:
        """Every tag in `repo`, mapped to the commit it resolves to.

        Read with `git ls-remote`, which returns the whole tag namespace in one
        request with annotated tags already peeled (the `^{}` lines). The REST
        alternative is paginated -- a prolific action has hundreds of tags -- and
        a scan that gave up after N pages would report a legitimately pinned
        commit as belonging to no release tag at all.
        """
        if repo in self._tags:
            return self._tags[repo]
        proc = subprocess.run(
            ["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"],
            capture_output=True, text=True, check=False, timeout=120,
        )
        if proc.returncode != 0:
            raise Unverifiable(f"cannot list tags of {repo}: {proc.stderr.strip()[:120]}")
        resolved: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            sha, _, ref = line.partition("\t")
            if not ref.startswith("refs/tags/"):
                continue
            name = ref[len("refs/tags/"):]
            # `<tag>^{}` is the peeled commit of an annotated tag and must win
            # over the tag object's own SHA.
            resolved[name.removesuffix("^{}")] = sha
        self._tags[repo] = resolved
        return resolved

    def semver_tags_at(self, repo: str, sha: str) -> list[str]:
        """Semver tag names in `repo` whose target commit is `sha`."""
        return sorted(
            name for name, target in self.tags(repo).items()
            if target == sha and SEMVER_TAG.match(name)
        )

    def release(self, repo: str, tag: str) -> tuple[dt.datetime, bool]:
        """`(published_at, immutable)` for `tag`'s release."""
        rel = self.get(f"/repos/{repo}/releases/tags/{tag}")
        if not isinstance(rel, dict) or "_error" in rel:
            err = rel.get("_error", "unknown error") if isinstance(rel, dict) else "bad response"
            raise Unverifiable(f"no release for {tag} ({err})")
        stamp = rel.get("published_at")
        if not stamp:
            raise Unverifiable(f"release {tag} has no published_at")
        return parse_stamp(stamp), bool(rel.get("immutable"))

    def commit_date(self, repo: str, sha: str) -> dt.datetime:
        """Latest of a commit's author and committer dates."""
        data = self.get(f"/repos/{repo}/commits/{sha}")
        if not isinstance(data, dict) or "_error" in data:
            err = data.get("_error", "unknown error") if isinstance(data, dict) else "bad response"
            raise Unverifiable(f"cannot read commit {sha[:12]} ({err})")
        commit = data.get("commit", {})
        stamps = [
            commit.get(role, {}).get("date")
            for role in ("committer", "author")
        ]
        dates = [parse_stamp(s) for s in stamps if s]
        if not dates:
            raise Unverifiable(f"commit {sha[:12]} has no timestamp")
        return max(dates)


def parse_stamp(stamp: str) -> dt.datetime:
    return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def load_allowlist(path: str) -> dict[str, str]:
    """Read `owner/repo: reason` lines from the allowlist file.

    Read line by line rather than as YAML because the format is one line per
    exemption and the reason is free text; comments and blank lines are ignored,
    and anything else must be `key: reason`.
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


def uses_in_file(path: str) -> list[tuple[int, str]]:
    """Every `(line, ref)` a YAML file declares, found by parsing it.

    Scanning lines with a regex was wrong in kind rather than in detail. `uses`
    is a YAML key, and YAML offers more ways to write one than a pattern can
    chase: a flow mapping (`- {uses: o/r@ref}`), a quoted key, a value on the
    following line, a folded scalar, an alias. Each form the pattern missed was
    an action the workflow executes and the check said nothing about, which is
    the one failure mode a security gate must not have. So the file is composed
    into a node tree instead, and every `uses` key is found at any depth whatever
    syntax spelled it.

    A file that does not parse raises `Unverifiable`: it is either not the YAML
    we take it for or it holds something this scanner does not model, and both
    are reasons to go red rather than to look away.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        roots = list(yaml.compose_all(text))
    except yaml.YAMLError as exc:
        raise Unverifiable(f"cannot parse {path}: {str(exc).splitlines()[0]}") from exc

    found: list[tuple[int, str]] = []

    def walk(node: yaml.Node | None, seen: set[int]) -> None:
        # An anchor makes one node appear in several places; visiting it twice
        # would report the same reference twice.
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if (isinstance(key, yaml.ScalarNode) and key.value == "uses"
                        and isinstance(value, yaml.ScalarNode)):
                    found.append((value.start_mark.line + 1, value.value.strip()))
                walk(value, seen)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                walk(item, seen)

    for root in roots:
        walk(root, set())
    return sorted(found)


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


def changed_files(base: str, paths: list[str]) -> list[str]:
    """Workflow files under `paths` that changed relative to `base`.

    Raises `Unverifiable` rather than returning nothing when git cannot answer:
    a shallow clone or an unfetched base ref would otherwise yield an empty file
    list, and "inspected nothing" would report as a pass.
    """
    def git(*args: str) -> str:
        proc = subprocess.run(
            ["git", *args], capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            raise Unverifiable(
                f"git {' '.join(args)} failed: {proc.stderr.strip()[:200]}. "
                "A PR-scoped run needs the base ref fetched (fetch-depth: 0)."
            )
        return proc.stdout

    merge_base = git("merge-base", "HEAD", base).strip()
    diff = git("diff", "--name-only", "--diff-filter=d", merge_base, "HEAD").split()
    return [
        f for f in diff
        if f.endswith((".yml", ".yaml")) and os.path.exists(f)
        and any(under(f, root) for root in paths)
    ]


def under(path: str, root: str) -> bool:
    """Whether `path` is `root` or sits inside it, comparing whole segments."""
    path = os.path.normpath(path)
    root = os.path.normpath(root)
    return root == "." or path == root or path.startswith(root + os.sep)


def verify_ref(gh: GitHub, ref: str, min_age: dt.timedelta, allow: dict[str, str],
               now: dt.datetime, internal_owner: str | None = None,
               require_immutable: bool = False) -> tuple[str, str, list[str]]:
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

    try:
        tags = gh.semver_tags_at(repo, pin)
    except Unverifiable as exc:
        return "fail", str(exc), []
    if not tags:
        return "fail", "pinned SHA is not the target of any vX.Y.Z tag", []

    # Several tags can share a commit (v1.2.3 and 1.2.3, or a retag). The pin is
    # acceptable if any one of them clears every gate, so a tag without a release
    # does not condemn a commit that another tag does vouch for.
    problems = []
    for tag in tags:
        try:
            problem = check_tag(gh, repo, pin, tag, min_age, now, require_immutable)
        except Unverifiable as exc:
            problems.append(str(exc))
            continue
        if problem is None:
            return "pass", verdict_detail(gh, repo, pin, tag, now), tags
        problems.append(problem)
    return "fail", "; ".join(problems), tags


def check_tag(gh: GitHub, repo: str, sha: str, tag: str, min_age: dt.timedelta,
              now: dt.datetime, require_immutable: bool) -> str | None:
    """`None` if `tag` vouches for `sha`, else why it does not."""
    published, immutable = gh.release(repo, tag)
    age = now - published
    if age < min_age:
        return f"{tag} published {age.days}d ago, under minimum"
    if immutable:
        return None
    if require_immutable:
        return f"{tag} is not an immutable release"
    # A mutable tag could have been moved onto a commit created long after the
    # release it now claims; that ordering is the detectable part.
    committed = gh.commit_date(repo, sha)
    if committed > published + CLOCK_SKEW:
        return (
            f"{tag} was published {published:%Y-%m-%d} but its commit dates from "
            f"{committed:%Y-%m-%d} -- the tag appears to have been moved"
        )
    return None


def verdict_detail(gh: GitHub, repo: str, sha: str, tag: str, now: dt.datetime) -> str:
    published, immutable = gh.release(repo, tag)
    basis = "immutable release" if immutable else "mutable tag, commit consistent"
    return f"{tag} published {(now - published).days}d ago ({basis})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", default=[".github"],
                    help="workflow/action files or directories to scan")
    ap.add_argument("--base", help="only check workflow files changed vs this ref")
    ap.add_argument("--min-age-days", type=int, default=7)
    ap.add_argument("--allowlist", default=".github/action-pin-allowlist.yml")
    ap.add_argument("--internal-owner", default=os.environ.get("GITHUB_REPOSITORY_OWNER"),
                    help="owner whose own actions are first-party and skipped")
    ap.add_argument("--require-immutable", action="store_true",
                    help="accept only immutable releases, whose tag cannot move")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    args = ap.parse_args()

    paths = args.paths or [".github"]
    try:
        files = changed_files(args.base, paths) if args.base else workflow_files(paths)
    except Unverifiable as exc:
        print(f"FAIL cannot determine which files to check -- {exc}")
        return 1

    gh = GitHub(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    allow = load_allowlist(args.allowlist)
    min_age = dt.timedelta(days=args.min_age_days)
    now = dt.datetime.now(dt.timezone.utc)

    findings: list[Finding] = []
    for path in files:
        try:
            refs = uses_in_file(path)
        except Unverifiable as exc:
            findings.append(Finding(path, 0, path, "fail", str(exc)))
            continue
        for lineno, ref in refs:
            status, detail, tags = verify_ref(
                gh, ref, min_age, allow, now,
                args.internal_owner, args.require_immutable,
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
