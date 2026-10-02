# P6 Cutover Runbook: IRS Workflow Migration (M1-Active)

## 1. Pre-Cutover Verification & Backups
- Verify legacy automation and controller are stopped/paused (`status == PAUSED`). No live LLM status polls or heartbeat jobs.
- Save exact local backups before modification:
  - Legacy controller JSON snapshot: `.local/P6-backups/legacy-controller-before.json`
  - Legacy automation TOML snapshot: `.local/P6-backups/automation-before.toml`
- Verify candidate role bindings: overview (`01a0fc28-4bb4-7a61-bf92-1ab8c8a5c2a9`), approval (`01a0fc28-a09d-77c0-b6af-0d29cc16864d`), acceptance (`01a0fc28-f069-76f0-b292-f100706d7d42`) are registered, typed, and distinct.

## 2. Gate Review Provenance & Approval Scope
- Validate host GPT gates V01–V09 using immutable public proof and private trusted review provenance (do not claim unverified model PASS).
- V05 applies strictly to candidate fixture scope; general business write runs remain disabled.
- C16 global policy remains untouched. V10 compared-baseline block does not block P6 (runner requires V01–V09; full cost goal unproven).
- Human authorization scope: Rely on existing user approval for migration plan C13/C15 and paused cutover. Do not request redundant approval or fabricate new click events; business execution resume remains unauthorized.

## 3. Ordered Cutover Application
The controller, automation and ledger are separate resources; backups and ordered verification provide recovery, not a cross-resource atomic transaction.

1. Apply `legacy-routing-patch.json` strictly as additions to legacy controller status JSON. Retain historical fields, policies, quota, env, and human history intact.
2. Update legacy automation prompt via API using `automation-retirement-prompt.txt`, keeping status `PAUSED` and preserving model, RRULE, notify, project, and cwds.
3. Ingest the validated cutover event through `runner.py`; the event ledger is appended first and state.json is derived:
   - Set generation: `m1-active`
   - Set owner: `runner`
   - Set `businessPaused: true`, `tools: false`
4. Commit old-status migration receipt.

## 4. Post-Cutover Read-Only Checks
- Verify single authoritative owner (`runner`) and three distinct active roles.
- Verify original B04 git HEAD, tree, and business status remain completely unchanged.
- Verify original control-directory change is limited to the authorized single C13 status file; product repository remains unchanged.
- Verify automation status is `PAUSED` and the old00 handoff task is inactive; core idle causes zero model calls, without claiming a full-machine process census.
- Preserve unknown HTML-browser visual state without claiming full visual gate PASS; no resume flags set.

## 5. Rollback Procedure
- If any check fails prior to or during cutover, halt immediately before state transition:
  - Restore legacy controller JSON strictly from saved backup.
  - Restore automation via API using original full fields and status `PAUSED`.
  - Do not delete scripts or issue blanket rejections for future valid cutovers.

## 6. Post-Cutover Target State
- Legacy 00 controller is retired to `historical_read_only`.
- New 00 overview acts as front door; approval and acceptance bound to confirmed UI role IDs.
- Gemini execution restricted to explicit bounded tasks under review; any business unpause requires explicit human authorization.
- Autodrive and polling daemons remain disabled; future activation requires a new explicit user authorization.
