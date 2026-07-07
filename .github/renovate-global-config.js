// Self-hosted Renovate global configuration.
//
// This config is used by the self-hosted Renovate runner workflow
// (.github/workflows/renovate.yml). It controls which repositories
// are managed and which post-upgrade commands are permitted.
//
// Per-repo behavior (package rules, schedules, grouping) is still
// defined in each repository's own renovate.json — this file only
// governs the self-hosted runner itself.

module.exports = {
  platform: "github",

  // Explicit repo list — add repos here as they migrate from the
  // Mend-hosted Renovate app to the self-hosted runner.
  repositories: ["workos/workos"],

  // Commands that postUpgradeTasks may execute. Each entry is a
  // regex tested against the resolved command string.
  allowedCommands: [
    "^node common/scripts/install-run-rush\\.js update$",
  ],
};
