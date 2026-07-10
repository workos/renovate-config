// Self-hosted Renovate global configuration.
//
// This config is used by the self-hosted Renovate runner workflow
// (.github/workflows/renovate.yml). It controls which repositories
// are managed and which post-upgrade commands are permitted.
//
// Per-repo behavior (package rules, schedules, grouping) is still
// defined in each repository's own renovate.json — this file only
// governs the self-hosted runner itself.

// postUpgradeTasks (in-container `rush update`) resolve packages through
// the Socket Firewall via the ~/.npmrc bind-mounted by renovate.yml. If
// the token is missing, that .npmrc would carry an empty authToken and
// installs would fail with 401s — or, if the .npmrc write is ever
// skipped, silently resolve via registry.npmjs.org and bypass the
// firewall entirely (INFRA-5233). Refuse to run instead.
if (!process.env.SOCKET_FIREWALL_TOKEN) {
  // Renovate logs an Error thrown from a config file only at DEBUG level
  // before dying with a generic "Error parsing config file" — print the
  // real reason to stderr so it shows in the workflow log at any level.
  console.error(
    "FATAL: SOCKET_FIREWALL_TOKEN is not set. Refusing to run: rush " +
      "lockfile updates would bypass the Socket Firewall (INFRA-5233)."
  );
  throw new Error(
    "SOCKET_FIREWALL_TOKEN is not set. Refusing to run: rush lockfile " +
      "updates would bypass the Socket Firewall (INFRA-5233)."
  );
}

// Daytime debug mode. The night-only schedule makes pipeline changes cost
// a full day per validation cycle. Setting the repo variable
// RENOVATE_WORKFLOW_DEBUG to "true" (a) lets renovate.yml's half-hourly
// cron firing through and (b) force-overrides the repo-level schedule
// below so those runs do real work immediately. Set it back to "false"
// when done — left on, it applies to night runs too.
const debugMode = process.env.RENOVATE_WORKFLOW_DEBUG === "true";
if (debugMode) {
  console.error(
    "RENOVATE_WORKFLOW_DEBUG=true — schedule override active: Renovate " +
      "will open/update PRs at any time of day and the hourly PR-creation " +
      "limit is lifted. Set the repo variable back to false after testing."
  );
}

module.exports = {
  platform: "github",

  // Explicit repo list — add repos here as they migrate from the
  // Mend-hosted Renovate app to the self-hosted runner.
  repositories: ["workos/workos"],

  // Commands that postUpgradeTasks may execute. Each entry is a
  // regex tested against the resolved command string.
  allowedCommands: [
    // The slim renovate image has no npm on the exec PATH; install-tool
    // installs node+npm in-container so install-run-rush can bootstrap.
    // Pinned to an explicit version (not postUpgradeTasks.installTools)
    // because branch-mode tasks resolve installTools with no version
    // constraints — "latest stable node" would eventually jump past
    // rush's hard `>=24.0.0 <25.0.0` range and break every lockfile
    // update org-wide. Keep the version passed by workos/workos in sync
    // with its .nvmrc.
    "^install-tool node \\d+\\.\\d+\\.\\d+$",
    "^node common/scripts/install-run-rush\\.js update$",
  ],

  // Per-command ceiling (minutes) for child processes Renovate execs,
  // postUpgradeTasks included. The default is 15; 20 gives a cold
  // in-container rush update headroom while keeping one branch's worst
  // case (2 commands x 20 min) inside the 60-minute App-token/job
  // window. Hung commands across SEVERAL branches can still hit the job
  // timeout mid-run — that self-heals on the next hourly run.
  executionTimeout: 20,

  // Routing the token through `secrets` gets it redacted in Renovate's
  // logs; customEnvVariables alone would print it at debug level.
  secrets: {
    SOCKET_FIREWALL_TOKEN: process.env.SOCKET_FIREWALL_TOKEN,
  },

  // Env forwarded to postUpgradeTasks child processes. Renovate strips
  // the container env down to a fixed allowlist (PATH, HOME, CI,
  // proxies, COREPACK_*, PNPM_*) — NODE_OPTIONS and NPM_CONFIG_* do NOT
  // pass through on their own.
  customEnvVariables: {
    SOCKET_FIREWALL_TOKEN: "{{ secrets.SOCKET_FIREWALL_TOKEN }}",
    // inngest-cli's postinstall spawns a download that can hang forever
    // in headless environments.
    SKIP_POSTINSTALL: "1",
    // Parity with workos/workos verify-lockfile.yml — rush update on the
    // monorepo needs the heap headroom.
    NODE_OPTIONS: "--max-old-space-size=4096",
  },

  // Debug-mode overrides must go through `force` — plain global config
  // is only a default and loses to the repo-level preset (which is
  // where the night-window schedule lives). prHourlyLimit 0 disables
  // the per-hour PR-creation cap so each debug run can open work;
  // prConcurrentLimit (10, repo config) still bounds open PRs. The
  // 7-day minimum release age is deliberately NOT lifted.
  ...(debugMode
    ? {
        force: {
          schedule: ["at any time"],
          prHourlyLimit: 0,
        },
      }
    : {}),
};
