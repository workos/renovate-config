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
- **Does not affect non-GitHub-Actions package managers.** The automerge and update-type rules are scoped via `matchManagers: ["github-actions"]`. Repos that extend this preset can layer their own rules for npm/pip/etc. on top.

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

## Prerequisites

The [Mend Renovate GitHub App](https://github.com/apps/renovate) must be installed on your repo (or installed org-wide). Check at the [Mend dashboard](https://developer.mend.io/github/workos).

## Changing the policy

Open a PR against this repo. Once merged, the change applies to every consuming repo on Renovate's next run.
