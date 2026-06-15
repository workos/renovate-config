# workos/renovate-config

Shared [Renovate](https://docs.renovatebot.com/) configuration presets for WorkOS repositories.

## Purpose

Centralize dependency-management policy across the org so that a single edit propagates to every consuming repo. This repository provides two presets:

| Preset | File | Best for |
|--------|------|----------|
| **Default** | `default.json` | Internal repositories with conservative update policies |
| **Public** | `public.json` | Public SDK and library repositories |

## Presets

### Default (`github>workos/renovate-config`)

The base preset that all WorkOS repositories can extend. It implements supply-chain hardening and conservative dependency management:

- **Pins GitHub Actions to full commit SHAs** via `helpers:pinGitHubActionDigests`. Any newly-added action referenced by tag (e.g. `actions/checkout@v6`) gets auto-pinned to a SHA with a version comment (`@<sha> # v6`).
- **Enforces a 7-day minimum release age** (`minimumReleaseAge: "7 days"`). New action releases are not eligible for auto-update until they have been published for 7+ days.
- **Treats missing release timestamps as "not yet eligible"** (`minimumReleaseAgeBehaviour: "timestamp-required"`) — the safer default introduced in Renovate 42.
- **Suppresses branches for not-yet-eligible updates** (`internalChecksFilter: "strict"`) so the inbox stays quiet.
- **Groups and auto-merges minor/patch/digest GitHub Actions updates** after CI passes. Major updates open a separate PR and require human review.
- **Patch-only policy for software dependencies by default** — minor and major dependency updates are disabled in the base preset. Patch updates are auto-merged after CI passes and the 7-day minimum age is met. Patch PRs are labeled `renovate/patch` at creation time. Consuming repos can override this to enable minor updates (see the monorepo example below).
- **Groups patch updates by dependency name** — all packages that use the same dependency are updated in a single PR. This ensures monorepos with version-consistency policies (e.g. Rush) pass lockfile validation. For single-package repos this is a no-op.
- **After-hours schedule** — Renovate only runs outside business hours for both US coasts: weekdays 9 PM–7 AM Eastern (6 PM–4 AM Pacific), and all day on weekends. The weekend window closes at 7 AM ET Monday.

### Public (`github>workos/renovate-config:public`)

Extends the default preset with a more permissive update policy suited for public SDK and library repositories:

- **Inherits all base protections** — SHA pinning, 7-day release age, GitHub Actions grouping.
- **Enables minor and major dependency updates** — overrides the default patch-only policy.
- **Automerges minor and patch updates** for all dependencies, grouped together.
- **Major updates require human review** — not auto-merged.
- **Monthly schedule** — runs on the 15th of each month before 12pm UTC.
- **No merge-queue labels** — does not add labels like `aviator/merge` since public repos typically merge PRs directly.

## How to use it

### For internal repositories

In your repo's `renovate.json`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["github>workos/renovate-config"]
}
```

### For public SDK / library repositories

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["github>workos/renovate-config:public"]
}
```

### GitHub Actions only

If you only want Renovate to manage GitHub Actions in your repo (and not, say, `package.json`), add `enabledManagers`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["github>workos/renovate-config"],
  "enabledManagers": ["github-actions"]
}
```

You can also override anything from either preset locally — `extends` is mergeable.

## Auto-approve workflow

For most repos, extending a preset is sufficient — Renovate will open and merge eligible PRs directly once CI passes.

Repos that use Aviator as their merge queue require an additional step, because Aviator enforces a minimum approval count before queuing a PR. For those repos, add a small workflow that calls the shared auto-approve workflow hosted here. Create `.github/workflows/renovate-auto-approve.yml` in your repo:

```yaml
name: Auto-approve Renovate PRs

on:
  pull_request:
    types: [opened, labeled]

jobs:
  auto-approve:
    uses: workos/renovate-config/.github/workflows/auto-approve-renovate.yml@main
    permissions:
      pull-requests: write
```

This workflow approves any PR opened by `renovate[bot]` that carries the `renovate/patch` or `renovate/minor` label, satisfying Aviator's approval precondition. Aviator then queues the PR once CI passes.

## Prerequisites

The [Mend Renovate GitHub App](https://github.com/apps/renovate) must be installed on your repo (or installed org-wide). Check at the [Mend dashboard](https://developer.mend.io/github/workos).

## Changing the policy

Open a PR against this repo. Once merged, the change applies to every consuming repo on Renovate's next run.
