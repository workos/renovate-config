# workos/renovate-config

Shared [Renovate](https://docs.renovatebot.com/) configuration preset for WorkOS repositories.

## Purpose

Centralize GitHub Actions dependency-management policy across the org so that a single edit propagates to every consuming repo. The preset implements supply-chain hardening for GitHub Actions dependencies.

## What the preset does

- **Pins GitHub Actions to full commit SHAs** via `helpers:pinGitHubActionDigests`. Any newly-added action referenced by tag (e.g. `actions/checkout@v6`) gets auto-pinned to a SHA with a version comment (`@<sha> # v6`).
- **Enforces a 7-day minimum release age** (`minimumReleaseAge: "7 days"`). New action releases are not eligible for auto-update until they have been published for 7+ days. Each version waits 7 days *individually*, so a fast-releasing action stays N versions behind rather than getting stuck.
- **Treats missing release timestamps as "not yet eligible"** (`minimumReleaseAgeBehaviour: "timestamp-required"`) — the safer default introduced in Renovate 42.
- **Suppresses branches for not-yet-eligible updates** (`internalChecksFilter: "strict"`) so the inbox stays quiet. Pending updates are visible on the Renovate Dependency Dashboard if enabled.
- **Groups and auto-merges minor/patch/digest GitHub Actions updates** after CI passes. Major updates open a separate PR and require human review.
- **Auto-merges patch updates for software dependencies** (npm, pip, Go modules, etc.) after CI passes and the 7-day minimum age is met. Minor and major dependency updates open a PR and require human review. Patch PRs are labeled `renovate/patch` and `aviator/merge` at creation time.

## How to use it

In your repo's `renovate.json`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["github>workos/renovate-config"]
}
```

If you only want Renovate to manage GitHub Actions in your repo (and not, say, `package.json`), add `enabledManagers`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["github>workos/renovate-config"],
  "enabledManagers": ["github-actions"]
}
```

You can also override anything from the preset locally — `extends` is mergeable.

## Auto-approve workflow

For most repos, extending this preset is sufficient — Renovate will open and merge eligible patch PRs directly once CI passes.

Repos that use Aviator as their merge queue require an additional step, because Aviator enforces a minimum approval count before queuing a PR. For those repos, add a small workflow that calls the shared auto-approve workflow hosted here. Create `.github/workflows/renovate-auto-approve.yml` in your repo:

```yaml
name: Auto-approve Renovate patch PRs

on:
  pull_request:
    types: [opened, labeled]

jobs:
  auto-approve:
    uses: workos/renovate-config/.github/workflows/auto-approve-renovate.yml@main
    permissions:
      pull-requests: write
```

This workflow approves any PR opened by `renovate[bot]` that carries the `renovate/patch` label, satisfying Aviator's approval precondition. Aviator then queues the PR once CI passes.

## Prerequisites

The [Mend Renovate GitHub App](https://github.com/apps/renovate) must be installed on your repo (or installed org-wide). Check at the [Mend dashboard](https://developer.mend.io/github/workos).

## Changing the policy

Open a PR against this repo. Once merged, the change applies to every consuming repo on Renovate's next run.
