## [Unreleased]

### Fixed

- `threatlocker_audit_file_history` sent only `fullPath` to
  `auditLog.getFileHistory`. Portal
  `GET /ActionLog/ActionLogGetAllForFileHistoryV2` returns HTTP 417
  "Missing Parameters. Unable to load details." unless `fullPath` is
  paired with `hostname` or `computerId` ([WYREAI-386](https://linear.app/wyre-ai/issue/WYREAI-386/epion-cw-automate-mcp-terminated-connection-interrupted-after-sep-9)).
  The tool now requires one of those identifiers (both may be sent) and
  calls `getFileHistory({ fullPath, hostname?, computerId?, sourceTableId?, pageNumber?, pageSize? })`.
  A fullPath-only call is rejected in the handler and is not sent.
  **SDK dependency is intentionally still `@wyre-ai/node-threatlocker@^1.0.7`.**
  That is the latest GitHub Packages release; its `getFileHistory` still
  takes a string and is the 417. The object form ships in
  [node-threatlocker#32](https://github.com/WYRE-AI/node-threatlocker/pull/32)
  (`fix!:`, draft, not published). semantic-release will publish that
  commit as **2.0.0**, not a 1.x, and `^1.0.7` will not install it.
  This repo's release practice is a caret range on the published
  GitHub Packages tarball (`npm ci` in CI and `npm ci --ignore-scripts`
  in the Docker image). A git pin of the unpublished branch is not used:
  the SDK gitignores `dist/`, and the image build skips lifecycle
  scripts, so a git install would ship without a build. Before this
  change is released, bump the dependency to `^2.0.0` and regenerate
  `package-lock.json` once 2.0.0 is on GitHub Packages. Do not release
  this MCP against 1.0.7.
- `threatlocker_approvals_pending_count`, `threatlocker_audit_file_history`,
  `threatlocker_organizations_for_move_computers`, and
  `threatlocker_computer_groups_dropdown` called SDK methods that don't
  exist (`approvalRequests.pendingCount`, `auditLog.fileHistory`,
  `organizations.forMoveComputers`, `computerGroups.dropdown`), throwing
  `... is not a function`. These tools were scaffolded against guessed
  method names before `@wyre-ai/node-threatlocker` was published;
  the real methods are `getPendingCount`, `getFileHistory`,
  `listForMoveComputers`, and `getDropdown`. Fixed all four call sites.
- `threatlocker_computers_get_checkins` called
  `client.computers.getCheckins(computerId, { pageNumber, pageSize })` —
  a two-argument call — but the SDK method takes a single params object.
  `computerId` was silently dropped, and the API rejected the resulting
  request as a 400 Bad Request. Fixed to pass one params object; requires
  `@wyre-ai/node-threatlocker@^1.0.7` (or later), which also fixes
  the SDK-side body-building bug that dropped `computerId` even when called
  correctly — see that package's changelog.
- `threatlocker_computer_groups_list` returning `[]` despite computers being
  assigned to real groups, and `threatlocker_organizations_get_auth_key`
  returning an empty key, were root-caused to `node-threatlocker` bugs (wrong
  organization-scoping header name; a response-shape assumption that didn't
  match the real bare-array API contract) — fixed there, no code change
  needed in this repo beyond picking up the dependency bump.
- **This repo silently stopped receiving any SDK updates since the
  WYRE-AI org migration.** `node-threatlocker` renamed its published npm
  package from `@wyre-technology/node-threatlocker` to
  `@wyre-ai/node-threatlocker` at that migration (v1.0.6), but this repo's
  `package.json`/`package-lock.json`/import in `src/utils/client.ts` were
  never updated — `npm install` kept happily resolving the old scope's last
  published version (1.0.5) forever, since GitHub Packages treats a scope
  rename as a distinct package, not a redirect. No error, no warning: every
  build since has been silently frozen on a two-week-stale SDK, missing
  1.0.6 and this session's 1.0.7 org-scoping-header fix. Repointed to
  `@wyre-ai/node-threatlocker@^1.0.7` (`package.json`, `vitest.config.ts`'s
  test-stub alias, the stub file's own comment) and regenerated the lockfile
  against the real published package.

### Added

- Handler-invocation test coverage for all five tool domains
  (`approval_requests`, `audit_log`, `computer_groups`, `computers`,
  `organizations`). Each exported `handleCall` is now invoked directly
  against a mocked `getClient()`, asserting outbound call shape (method,
  args/params) and response-transformation (what is returned to the MCP
  caller), plus default/elicitation-fallback branches and the
  unknown-tool error path. No production code changed.

## [1.2.5](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.2.4...v1.2.5) (2026-07-22)


### Bug Fixes

* route API calls to the tenant's ThreatLocker portal instance ([#32](https://github.com/wyre-technology/threatlocker-mcp/issues/32)) ([c135eb6](https://github.com/wyre-technology/threatlocker-mcp/commit/c135eb69c416b106eef25693c918477d5cafdab0)), closes [wyre-technology/msp-claude-plugins#131](https://github.com/wyre-technology/msp-claude-plugins/issues/131)

## [1.2.4](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.2.3...v1.2.4) (2026-07-19)


### Bug Fixes

* **lint:** remove stale [@ts-expect-error](https://github.com/ts-expect-error) and TODO for published SDK ([#35](https://github.com/wyre-technology/threatlocker-mcp/issues/35)) ([4898082](https://github.com/wyre-technology/threatlocker-mcp/commit/4898082d1d1762bf0da0081ee07a93bc6148e6ce))

## [1.2.3](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.2.2...v1.2.3) (2026-07-18)


### Bug Fixes

* **build:** ignoreDeprecations must be "6.0", not "5.0" ([#34](https://github.com/wyre-technology/threatlocker-mcp/issues/34)) ([f1cfc5c](https://github.com/wyre-technology/threatlocker-mcp/commit/f1cfc5c3355e267e94c5ac1ee1594d1ab4ed04ff))
* **security:** request-scoped credentials via AsyncLocalStorage to close cross-tenant leak ([#29](https://github.com/wyre-technology/threatlocker-mcp/issues/29)) ([868ee44](https://github.com/wyre-technology/threatlocker-mcp/commit/868ee44e0b3a0c9b82159c8268cf96696d4212aa))
* **security:** SHA-pin auto-add-to-project.yml [@main](https://github.com/main) -> [@6ae1533dd72f](https://github.com/6ae1533dd72f) (warden C-4) ([#26](https://github.com/wyre-technology/threatlocker-mcp/issues/26)) ([85ad6d1](https://github.com/wyre-technology/threatlocker-mcp/commit/85ad6d16b043246910c70cec80a044e90f25f27b))

## [1.2.2](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.2.1...v1.2.2) (2026-05-22)


### Bug Fixes

* set released=true only when semantic-release creates a new version ([b4d51a2](https://github.com/wyre-technology/threatlocker-mcp/commit/b4d51a2b2107300f2f41f9527c6f1e96fb0a737d))
* use block scalar for PRE_VERSION capture to avoid shell quoting issue ([0394bce](https://github.com/wyre-technology/threatlocker-mcp/commit/0394bce348f3d647befd91506d96190b48660b7b))

## [1.2.1](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.2.0...v1.2.1) (2026-05-22)


### Bug Fixes

* shorten server.json description to <=100 chars for MCP registry validation ([6374177](https://github.com/wyre-technology/threatlocker-mcp/commit/63741778064d2f14e2d6b928e52e4874cd486f7a))

# [1.2.0](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.1.0...v1.2.0) (2026-05-22)


### Features

* **ci:** make MCP Registry publish reliable ([#9](https://github.com/wyre-technology/threatlocker-mcp/issues/9)) ([9d685eb](https://github.com/wyre-technology/threatlocker-mcp/commit/9d685ebe5f7150cf4063654c6ad9f18f5efd18c4)), closes [wyre-technology/.github#16](https://github.com/wyre-technology/.github/issues/16)

# [1.1.0](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.0.4...v1.1.0) (2026-05-21)


### Features

* add server.json for MCP Registry publication ([#8](https://github.com/wyre-technology/threatlocker-mcp/issues/8)) ([251c68a](https://github.com/wyre-technology/threatlocker-mcp/commit/251c68a3ae2acf95363bed4255513e1560896d0f))

## [1.0.4](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.0.3...v1.0.4) (2026-05-18)


### Bug Fixes

* bump node-threatlocker to 1.0.2 and make /health a shallow probe ([#6](https://github.com/wyre-technology/threatlocker-mcp/issues/6)) ([f9aaa64](https://github.com/wyre-technology/threatlocker-mcp/commit/f9aaa645e2d19ef341f1571e84521bc189fee5e0))

## [Unreleased]

### Fixed

- Container crashed on startup with `ERR_MODULE_NOT_FOUND` for
  `@wyre-technology/node-threatlocker/dist/index.js`. The SDK had been
  published without its compiled `dist/` output. Bumped the dependency to
  `@wyre-technology/node-threatlocker@^1.0.2`, which ships the build output.
- `/health` returned `503` in gateway mode because it checked for
  startup-time credentials, which never exist in gateway mode (credentials
  arrive per-request via headers). This caused ACA to mark a working
  container Unhealthy. `/health` (and new alias `/healthz`) are now shallow
  liveness probes that return `200` whenever the process is up; credential
  status is still reported informationally in the body.

## [1.0.3](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.0.2...v1.0.3) (2026-05-05)


### Bug Fixes

* flatten navigation pattern for direct-install compatibility ([#4](https://github.com/wyre-technology/threatlocker-mcp/issues/4)) ([e074b8c](https://github.com/wyre-technology/threatlocker-mcp/commit/e074b8cbbc8d34d2948af4dd338d4ab0512bd4a9))

## [1.0.2](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.0.1...v1.0.2) (2026-05-04)


### Bug Fixes

* **add-to-project:** call shared reusable workflow ([#3](https://github.com/wyre-technology/threatlocker-mcp/issues/3)) ([eb9011c](https://github.com/wyre-technology/threatlocker-mcp/commit/eb9011c077b5cc7d76d3ffc54f673bcef59ce5b3))

## [1.0.1](https://github.com/wyre-technology/threatlocker-mcp/compare/v1.0.0...v1.0.1) (2026-05-01)


### Bug Fixes

* **docker:** add _authToken line to .npmrc ([e1d14a8](https://github.com/wyre-technology/threatlocker-mcp/commit/e1d14a8a2113920350cc8019e56d88a69f7fa654))

# 1.0.0 (2026-05-01)


### Features

* initial MCP server scaffold for ThreatLocker ([666e0b0](https://github.com/wyre-technology/threatlocker-mcp/commit/666e0b0fd3ff1e473099641532f52ce878a09e72))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial MCP server scaffold for ThreatLocker Portal API
- Support for computers domain (list, get, checkins)
- Support for computer groups domain (list, dropdown)
- Support for approval requests domain (list, get, pending count, permit applications)
- Support for audit log domain (search, get, file history)
- Support for organizations domain (list children, get auth key, move computers)
- Decision-tree navigation with `threatlocker_navigate` tool
- Gateway mode for multi-tenant deployments
- Elicitation infrastructure for interactive prompts
- Docker support with production-ready configuration
- Comprehensive logging and error handling
- TypeScript strict mode for type safety
