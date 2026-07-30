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

- **Pins GitHub Actions to full commit SHAs, tracked by semver tag** via `helpers:pinGitHubActionDigestsToSemver`. Any newly-added action referenced by tag (e.g. `actions/checkout@v6`) gets auto-pinned to a SHA with a version comment (`@<sha> # v6`), and the pinned SHA thereafter moves only as part of a semver update (`# v6` → `# v6.1.0`).
- **Enforces a 7-day minimum release age** (`minimumReleaseAge: "7 days"`). New action releases are not eligible for auto-update until they have been published for 7+ days.
- **Treats missing release timestamps as "not yet eligible"** (`minimumReleaseAgeBehaviour: "timestamp-required"`) — the safer default introduced in Renovate 42.
- **Suppresses branches for not-yet-eligible updates** (`internalChecksFilter: "strict"`) so the inbox stays quiet. A version update does not open a PR until it has already cleared the 7 days; the wait happens before PR creation, not in a pending check on an open PR.
- **Groups and auto-merges minor/patch GitHub Actions updates** after CI passes, in `github-actions versions`. Major updates are not opened at all.
- **Does not open bare digest re-points** (same tag, new commit). See [GitHub Actions update policy](#github-actions-update-policy).
- **Patch-only policy for software dependencies by default** — minor and major dependency updates are disabled in the base preset. Patch updates are auto-merged after CI passes and the 7-day minimum age is met. Patch PRs are labeled `renovate/patch` at creation time. Consuming repos can override this to enable minor updates (see [Enabling minor updates](#enabling-minor-updates)).
- **Groups patch updates by dependency name** — all packages that use the same dependency are updated in a single PR. This ensures monorepos with version-consistency policies (e.g. Rush) pass lockfile validation. For single-package repos this is a no-op.
- **After-hours schedule** — Renovate only runs outside business hours for both US coasts: weekdays 9 PM–7 AM Eastern (6 PM–4 AM Pacific), and all day on weekends. The weekend window closes at 7 AM ET Monday.
- **Security/vulnerability PRs follow the same schedule** — Renovate's built-in default creates vulnerability-fix PRs immediately (`schedule: []`), bypassing any configured schedule. This preset overrides that default so security PRs are only opened during the same after-hours window as regular updates.

### Public (`github>workos/renovate-config:public`)

Extends the default preset with a more permissive update policy suited for public SDK and library repositories:

- **Inherits all base protections** — SHA pinning, 7-day release age, GitHub Actions grouping.
- **Enables minor and major dependency updates** — overrides the default patch-only policy.
- **Automerges minor and patch updates** for all dependencies, grouped together.
- **Major updates require human review** — not auto-merged.
- **Monthly schedule** — runs on the 15th of each month before 12pm UTC.
- **No merge-queue labels** — does not add labels like `aviator/merge` since public repos typically merge PRs directly.
- **Security/vulnerability PRs fire immediately** — overrides the base preset's after-hours constraint so security fixes are not delayed in public repos.

## GitHub Actions update policy

Actions are SHA-pinned, but a SHA has no release date, so it cannot be aged. Renovate's `github-tags` datasource attaches no timestamp to a digest, which means `minimumReleaseAgeBehaviour: "timestamp-required"` holds every digest update pending forever — the `renovate/stability-days` check on a grouped `digest` PR can never pass, and grouping it with real version updates blocks those too.

The preset therefore splits actions updates into four buckets:

| Update | Behaviour | Why |
|--------|-----------|-----|
| `minor` / `patch` (semver tag) | 7-day age gate, grouped in `github-actions versions`, automerged | The tag has a release timestamp, so the age gate is real |
| `pin` / `pinDigest` | No age gate, grouped in `github-actions pins`, automerged | Pinning freezes the SHA the floating tag already resolves to — no new code |
| `digest` (tag re-pointed to a new commit) | Not opened | No timestamp to age against; automerging would merge a commit of unknown age, which is the tag-hijack shape SHA pinning exists to defend against |
| `major` | Not opened | Breaking changes; bump manually |

Consequences worth knowing:

- **A tag that is force-pushed to new commits is not followed.** That is deliberate: the pinned SHA keeps running the code we reviewed. It is also the reason to prefer actions published with [immutable releases](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/), whose tags cannot move.
- **An action that publishes no `X.Y.Z` tag gets no updates.** `helpers:pinGitHubActionDigestsToSemver` reads the version from the pin comment, so `# v3` is fine as long as the upstream repo tags full semver — Renovate resolves `v3` to e.g. `v3.4.1` on the next aged update. An action that only ever tags `v3` is frozen at its current SHA and has to be bumped by hand.

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

## Verifying action pins

The preset can only age an update it has a timestamp for. A bare digest — a 40-character SHA — has none, which is why `digest` updates are not opened at all (see the table above). That leaves one thing Renovate cannot vouch for: the SHA a pin resolved to in the first place. `pin`/`pinDigest` freezes whatever `v4` pointed at when Renovate looked, and if that tag had been moved onto a malicious commit, the pin preserves it.

`verify-action-pins` closes that from outside Renovate, using facts a SHA alone doesn't give you:

1. **Provenance** — the pinned SHA must be the exact target of a `vX.Y.Z` tag upstream. A commit no release tag points at is never something we meant to run.
2. **Age** — that tag's release must have been published at least 7 days ago, measured by the release's `published_at`.
3. **Binding** — the release has to be plausibly *about* the pinned commit. A `vX.Y.Z` tag is still a mutable ref: move `v4.3.1` onto a fresh commit and it satisfies (1) while inheriting the old release's timestamp for (2). So either the release is [immutable](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/) — the tag provably cannot have moved — or the commit must not be newer than the release that supposedly shipped it.

`published_at` is assigned by GitHub at publish time and isn't settable through the REST API, which is why it's the anchor rather than commit metadata: `GIT_COMMITTER_DATE` lets anyone backdate a freshly pushed commit.

That cuts both ways, and it's worth being precise about what (3) buys: for a non-immutable release it's a consistency check, not proof. It catches the naive hijack — fresh commit, tag moved onto it — but an attacker who backdates the commit passes it. Immutable releases are the only proof available today, and `require-immutable: true` insists on them; almost no upstream action has adopted them yet, so it currently fails nearly everything. Proving a tag never moved without trusting upstream metadata needs a first-seen ledger of `(action, tag) → SHA` recorded here, which is deliberately not in this change.

Add it to a repo with:

```yaml
name: Verify action pins

on:
  pull_request:

jobs:
  action-pins:
    uses: workos/renovate-config/.github/workflows/verify-action-pins.yml@main
```

If you pin that `uses:` to a SHA, pass the same SHA as `checker-ref` — a reusable workflow cannot see the ref it was called with (`github.workflow_ref` is the caller's), so the implementation it runs is a separate checkout that otherwise tracks `main`:

```yaml
  action-pins:
    uses: workos/renovate-config/.github/workflows/verify-action-pins.yml@<sha>
    with:
      checker-ref: <sha>
```

It reports as an ordinary status check, which is what makes it a usable automerge gate: Renovate won't merge a branch with a red status, so a pin whose release is younger than 7 days cannot land — and the check turns green by itself once the release ages, with no human step. Make it a required check to get the guarantee rather than the hint.

The check fails closed — no tag match, no release, no timestamp, no commit metadata, API errors, and a git failure that leaves it unsure which files changed are all failures. A check that goes green when it can't see the data converts an unknown into a tick. Genuine exceptions go in `.github/action-pin-allowlist.yml` (one `owner/repo: reason` per line; see [the example](verify-action-pins/action-pin-allowlist.example.yml)), where they're explicit and reviewable. Two actions in use today need one: `dopplerhq/cli-action` (only `v3`/`v4` tags, no `vX.Y.Z` releases) and `rubygems/configure-rubygems-credentials` (non-semver tags).

Workflows are parsed as YAML rather than pattern-matched line by line, so every form Actions accepts is covered — flow mappings, quoted keys, a value on the next line, anchors — and a file that doesn't parse is a failure rather than a file with no findings. That needs PyYAML, which GitHub-hosted runners ship; the action installs it if a self-hosted runner doesn't.

`docker://` container steps run third-party code the same way an action does, so a movable `:tag` fails; a `@sha256:...` digest passes, since a content-addressed image can't be retargeted (registries don't expose a release age to check, and the digest makes one unnecessary). Allowlist them by image name without the tag. No repo uses a `docker://` step today, so this costs nothing now and closes the gap before one does.

First-party `workos/*` references are skipped: they're covered by this check in the repository that owns them, and demanding a SHA for `workos/actions/...@main` would relocate the trust decision rather than strengthen it.

## Enabling minor updates

The default preset disables minor (and major) updates for software dependencies. To opt in to automerged minor updates in a consuming repo, add a `packageRules` entry that re-enables them **and** labels the PRs so the auto-approve workflow fires:

```json
{
  "packageRules": [
    {
      "description": "Enable and automerge minor updates, grouped by dependency name.",
      "matchManagers": ["!github-actions"],
      "matchUpdateTypes": ["minor"],
      "enabled": true,
      "groupName": "{{{depName}}}",
      "groupSlug": "{{{depNameSanitized}}}",
      "automerge": true,
      "addLabels": ["renovate/minor"]
    }
  ]
}
```

The `addLabels: ["renovate/minor"]` is required — without it the auto-approve workflow's label check will never match and PRs will sit without approval.

## Prerequisites

Repositories are managed by one of two Renovate runners:

| Runner | Repos | `postUpgradeTasks` | Setup |
|--------|-------|--------------------|-------|
| **Self-hosted** (`.github/workflows/renovate.yml`) | Listed in `.github/renovate-global-config.js` | Yes | See below |
| **Mend Renovate GitHub App** | All other repos | No | [Install the app](https://github.com/apps/renovate) |

### Self-hosted runner

The self-hosted runner is a scheduled GitHub Actions workflow in this repository that runs the Renovate Docker container. It supports `postUpgradeTasks` (e.g. `rush update` for lockfile generation), which the Mend-hosted app cannot provide.

**Configuration:**
- `.github/workflows/renovate.yml` — the workflow definition (schedule, runner, auth)
- `.github/renovate-global-config.js` — self-hosted global config (repo list, allowed commands)

**Required secrets (in this repo's Actions settings):**
- `RENOVATE_APP_PRIVATE_KEY` — private key for the GitHub App used by the runner
- `RENOVATE_APP_ID` — GitHub App ID (stored as a variable, not a secret)
- `SOCKET_FIREWALL_TOKEN` — token for the Socket Firewall npm registry proxy

**Adding a repo to the self-hosted runner:**
1. Add the repo to `repositories` in `.github/renovate-global-config.js`
2. Remove the repo from the Mend Renovate GitHub App's installation (Settings → Integrations → GitHub Apps → Renovate → Configure → deselect the repo)
3. If the repo needs post-upgrade commands, add the command regex to `allowedCommands` in the global config and add `postUpgradeTasks` to the repo's `renovate.json`

**Manual trigger:**
The workflow supports `workflow_dispatch` with optional dry-run and log-level inputs for testing.

### Mend Renovate GitHub App

For repos not yet migrated to self-hosted, the [Mend Renovate GitHub App](https://github.com/apps/renovate) must be installed on the repo (or installed org-wide). Check at the [Mend dashboard](https://developer.mend.io/github/workos).

## Changing the policy

Open a PR against this repo. Once merged, the change applies to every consuming repo on Renovate's next run.
