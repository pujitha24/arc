# Local Docker license behavior verification

Opt-in integration tests for the license lifecycle change tracked by Arc #1442. These
scripts exercise the checked-out production implementation. Historical reports
retain failures from earlier revisions; use the image provenance and assertion
details when comparing runs.

## Isolation and credentials

Run from this checkout. Requirements: Docker, Python 3.10+, OpenSSL, internet access
for the real activation service and initial image builds, approximately 8 CPUs and
16 GB RAM. Real keys must be supplied as file paths. Keys, admin tokens, caches,
SQLite files and fixture private signing material stay in a private state directory
outside the checkout. Never publish that directory or Docker inspect/env output.
Only the redacted reports and `*.redacted.log` files are shareable after scanning.

Use one key per installation. Real-key nodes use stable hostnames, MAC addresses,
CPU visibility and persistent data across restarts. Reusing a different state or
run ID can consume additional activation slots. The capacity case deliberately
attempts one additional reader for the three-machine key, then stops it. It does
not delete or revoke activation records. A redacted HTTP 403 is recorded as an
activation refusal with inconclusive capacity attribution.

Containers have the label `arc-license-tests=<run-id>`, bounded memory/CPU, and
loopback-only published ports. Container data is retained; test containers are
stopped after normal completion. On interruption, inspect and stop only resources
with the exact run label. Do not prune Docker or delete data to clean up.

## Real keys

Build the unmodified production image and cached builder stage:

```sh
docker build --build-arg VERSION=dde0bbeb -t arc-license-tests:dde0bbeb .
docker build --target builder -t arc-license-builder:dde0bbeb .
python3 scripts/license_docker/run.py --state /absolute/private-state/live \
  --run-id arc-license-live /absolute/.trial_key /absolute/.trial_key1 /absolute/.trial_key2
python3 scripts/license_docker/advanced.py --state /absolute/private-state/live \
  --run-id arc-license-live /absolute/.trial_key /absolute/.trial_key1 /absolute/.trial_key2
python3 scripts/license_docker/failover.py --state /absolute/private-state/live \
  --run-id arc-license-live /absolute/.trial_key /absolute/.trial_key1 /absolute/.trial_key2
```

Image tags identify the source revision tested in this investigation. Rebuild and
change tags/arguments when testing another revision. `advanced.py` expects the
recorded three-installation layout (license1 is the three-machine installation)
and a local SeaweedFS 4.47 image. It preserves RBAC configuration, configures S3
cold storage (using one existing Professional node as a dedicated compactor), creates two normally ingested files, daily-compacts them, migrates
them, verifies real S3 objects and queries after migration/restart. A query while
a hot copy remains is not proof of a cold read; inspect that observation too.

`failover.py` kills only the suite's primary container, keeping two Raft voters
alive. It observes the configured 30-second failover timeout for up to 65 seconds,
restores three writer voters, proves surviving quorum with a committed RBAC write,
checks the signed writer-failover entitlement, then restarts and checks row counts.
It does not write during the crash window, so it does not prove zero loss for
unacknowledged or concurrently buffered writes.

## Controlled expiry and authority failures

```sh
python3 scripts/license_docker/prepare_fixture.py --state /absolute/private-state/fixture-material
python3 scripts/license_docker/run_fixture.py --state /absolute/private-state/controlled \
  --material /absolute/private-state/fixture-material --run-id arc-license-fixtures
```

These use **synthetic keys**, a private local HTTPS authority, and two explicitly
test-only images. Go's build overlay changes the pinned public key in both images;
the fast image also changes validation cadence from four hours to two seconds.
The slow image retains the four-hour cadence, permitting a signed 45-second
expiry test with no subsequent authority request. No host clock is changed, no
real key is sent to the fixture, and no private signing key enters an image build
context. The fixture rejects keys without the `LOCAL-FIXTURE-` prefix.

The fast cases cover HTTP 503/429, malformed/null/HTML responses, bad signatures,
transport failure, both reactivation reasons, definitive rejection reasons,
recovery and outage restart after cached entitlement removal. Preservation checks require repeated requests from each machine and a sustained
health/cache/API observation window. Successful reactivation must install and
persist a different signed expiration. Existing containers must match the requested
image and environment; every resource mutation checks the ownership label.

## Guard probes

```sh
python3 scripts/license_docker/safety.py --report /absolute/private-state/guard-report.json
```

These create disposable sentinel containers/networks, prove foreign-resource
mutations and attachment are rejected, and check changed/removed environment
settings. The sentinels never run Arc or contact the license authority and are
removed in `finally`.

## Evidence and limits

`lifecycle_runtime.py` creates a new isolated three-installation project from
previously verified, redacted feature profiles, using separate paid/trial local
authorities. It checks day-8 serving ownership and absence of automatic writer
replacement, day-9 RBAC management, day-10 migration admission, final OSS ownership,
closed Raft ports, repeated restarts, license reactivation and suspended boot
recovery. It retains every created container and data directory for inspection.
The existing real-key and earlier synthetic projects are continuously watched;
their identities, images, start times and restart counters must stay unchanged.

The suite waits for the newly signed grace day on every participant before
asserting behavior. It retries only an explicit pre-admission retention-policy
adoption refusal during setup. It compares exact acknowledged record-ID sets and
queries thirty cold rows with a non-default S3 prefix. The read-only Go helper in
`ack_audit/` independently checks the union of retained Parquet namespaces. This
physical-preservation assertion is separate from the current owner's query set:
keeping expired cluster configuration can elect another node whose local OSS
history differs. No test claims that these later OSS histories are merged.
Build the auditor with `go build -o /absolute/path/ack-audit
./scripts/license_docker/ack_audit` and pass `--audit-binary` explicitly outside
this investigation's workspace. `--shared-unlimited` exercises an S3 hot backend
and shared-storage mode on the Unlimited installation; `--auto-node-ids` leaves
the configured node IDs empty and checks the generated participant identities.
`--crash-before-release` temporarily blocks one participant's local certificate
path with an empty directory, asserts that no Raft-off boot authority is issued,
kills only the fixture controller, removes the blocker and restarts it. The
subsequent assertions require actual recovery and a completed single-OSS handoff.

All accelerated lifecycle images overlay only the test trust key and validation
cadence. The lifecycle logic is the production code, without date overrides.
Authority clocks move forward; host and container clocks remain unchanged.

Each assertion writes its HTTP/body or independent file/signature observation to
JSON. `OBSERVED` is not `PASS`. Reports are separate for baseline, advanced,
failover and controlled tests. A nonzero exit can reflect a genuine unsupported
policy, an inconclusive probe, or a harness defect: classify it before concluding
that Arc is broken. Preserve original evidence when correcting a harness error.

The standard Docker build does not include the arcx extension artifact. A feature
bit does not prove SQL extension behavior. These runs do not test the future paid
UTC calendar grace period, day-8/9/10 stages, coordinated one-node OSS handoff,
reconciliation of writes after handoff, every scheduler execution, all storage
backends, TLS combinations, or a real lower-tier key. Actual real-key expiry dates
are reported without pretending they elapsed during this run.

## Uninterrupted real-key expiry soak

After all restart/crash cases finish, start each existing installation and the
observer once:

```sh
python3 scripts/license_docker/soak.py --state /absolute/private-state/live \
  --monitor-state /absolute/private-state/natural-expiry --run-id arc-license-live
```

This leaves three independent installations running: one real key per installation,
using the existing 11 Arc nodes and local S3 fixture. It does not allocate new
license identities. The observer source is copied into private state and hashed, so later checkout changes do not change the long-running process. It runs in a separate persistent Docker container,
without a Docker socket, clock capabilities or permission to restart Arc. Arc
processes keep their current restart policies; the observer alone can restart
following its own failure or a machine reboot, and records that discontinuity.

`latest.json` contains the most recent sample. Daily `events-*.jsonl`,
`alerts.jsonl`, the durable write-intent/acknowledgment ledger, initial process
start times and configuration digests remain in the private monitor directory.
The private configuration contains admin/scoped API tokens; do not publish it.
The observer writes only to a dedicated `license_soak_events` measurement in the
`license_soak` database. It never changes cluster or license configuration.

Normal cadence is 60 seconds for health/readiness/ingestion/counts, five minutes
for feature gates, roles/Raft, existing cold data, RBAC and read-only configuration
digests, and one hour for checking every confirmed probe ID. Within ten minutes
of each signed real expiry, sample cadence becomes five seconds and ID audits
run once a minute. Failures can make sampling slower; recorded timestamps define
the actual observation resolution. A decreased uptime, license-state change,
missing/duplicate rows, altered RBAC access, changed configuration digest or cold
read failure produces an alert. An outage is recorded rather than repaired.

There is no automatic stop date. To stop only observation:

```sh
docker stop arc-license-live-natural-expiry-observer
```

That command leaves Arc running. Natural expiration has not been tested until
those dates actually pass; fixture results are separate evidence. The future
paid grace/degradation stages are absent from the original ongoing-soak image
and cannot be claimed from that setup alone.

`soak.py --replace-observer` replaces only the collector and does not start or
repair stopped Arc/S3 services; their unavailability remains observable.

`prepare_fixture.py` now copies tracked build inputs from the current checkout
into the compatible Debian builder. Private signing keys and real credentials
stay outside the image contexts. Build provenance records the source revision
and working diff digest. `--image-prefix` and `--authority-image` isolate image
tags from earlier experiments.

`run_policy_fixture.py` exercises protocol 2 with synthetic paid and trial keys,
signed authority dates independent of the host date, bad/replayed proofs,
running-process outage preservation, cache-only restart refusal and recovery,
UTC grace phases, RBAC management gating and tiering admission. It also retains
failing requirements for day-8 role contraction and final OSS handoff until
their controller exists. A desired-policy health field does not satisfy these
requirements. It changes no host clock and never touches the real-key soak.

`run_cold_oss.py` generates thirty new synthetic Parquet rows with the Go helper
under `cold_fixture/`, uploads them to a separate disposable local S3 store, and
starts an unlicensed OSS binary with auth disabled, an empty metadata database,
`scan_timeout=5m` and S3 prefix `preserved/archive`. It checks actual SQL cold
reads before and after restart, refused tiering management and retained object
bytes. It never copies an existing installation's data or metadata.

## Three retained stacks: expected versus actual, 2026-11-05

Branch: `feat/license-three-stack-tests`, based on `feat/license-authority-time`
at `5008e591`. Only test infrastructure changes. The original branch remains at
that commit with a clean worktree; production `cmd/` and `internal/` files are
identical. The test images substitute a disposable public signing key and a
two-second validation interval. They are not production images.

The real keys are never sent to the local authorities. Their cached payloads
are independently verified with the production public key, then only tier,
feature set, limits and trial classification are copied into synthetic profiles.
Nominal deadlines are shifted to deterministic UTC test dates. This establishes
matching entitlements, not production issuance or activation-limit enforcement.

| Counterpart | Kind | Limits | Additional cluster | Authority |
|---|---|---|---|---|
| `.trial_key` | Paid Unlimited, 18 feature flags | Unlimited cores/machines | 3 writers + 2 readers | Local paid |
| `.trial_key1` | Paid Professional, 11 feature flags | 32 cores, 3 machines | 2 writers + compactor | Local paid |
| `.trial_key2` | Trial Professional, 11 feature flags | 32 cores, 5 machines | 2 writers + compactor + reader | Local trial |

All twelve additional Arc containers, both local authorities and the synthetic
S3 fixture remain running. Networks are internal-only, on `10.251.144.0/24`,
`10.251.145.0/24` and `10.251.146.0/24`. Host access uses the private bridge IPs
because this Docker configuration suppresses published ports on internal
networks. Authority TLS verification remains enabled. No host/container system
clock was changed and no existing real-server stack was stopped or deleted.

| Condition | Expected | Observed |
|---|---|---|
| Paid expiration date, grace days 1–7 | Retain licensed operation | PASS: APIs, real writes/reads, RBAC, governance and manual job execution |
| Paid day 8 onward | One serving endpoint per role; no HA/load balancing | FAIL: multiple writer/reader endpoints still serve data; Unlimited failover worker remains running |
| Paid day 9 | RBAC management read-only; existing data authorization retained | PASS: management and membership grants refused; existing allowed/denied reads preserved |
| Paid day 10 | Refuse new tier migrations, keep cold data readable | PASS: API refused migration; eligible compacted files remained hot through an observed scheduled tick on both paid stacks |
| Paid day 14/final cutoff | Remain entitled until final UTC cutoff; then expire without needing a new grant | PASS: signed pre-cutoff anchors expired through elapsed time during an authority outage |
| Trial while paid dates advance | Independent clock and no premature expiry | PASS |
| Trial exact cutoff and days 1, 7, 8, 14 | Immediate expiry, no grace | PASS: elapsed-time cutoff and subsequent definitive server refusals |
| Final paid/trial expiry | One standalone OSS owner, Raft stopped, peers fenced | FAIL: current code retains the cluster and Raft; it does not complete the required handoff |
| Unsupported governance after expiry | Retain config but make its licensed row-cap function dormant | PASS: row cap stops applying; RBAC data restrictions continue |
| Data/config/history preservation | Keep acknowledged data, original stable config rows and completed history | PASS for finite fixtures: 40/40/32 acknowledged main-data IDs present exactly once; 30 cold rows per stack; SQLite integrity and row fingerprints retained |

**A health tier of `oss` is not evidence of an OSS runtime conversion.** These
tests check cluster/Raft/readiness and actual per-node operations separately.

The main corrected matrix records **657 PASS / 33 FAIL / 23 OBSERVED**, from
harness revision `73e7c104`. The 33 failures are repeated checks of the known
role-contraction, failover-shutdown and final ownership/fencing gaps, not 33
distinct defects. A targeted recheck at `894386cd` records **39 PASS / 1 OBSERVED**:
unique retention probes prove old rows disappear/current rows remain, and newly
completed CQ execution IDs with positive output prove fresh background work on
all three licensed stacks. It does not retroactively upgrade earlier checks
that observed only HTTP 200 or historical CQ entries. Synthetic renewal restored
feature gates without restarting Arc; because no OSS handoff occurred, this does
not establish safe inverse-handoff reconciliation.

Ten harness regression tests pass, including no-op retention, stale CQ history,
zero-output CQ execution, elapsed-time resume guards, bounded diagnostic history,
clock-state restoration and incomplete participant manifests. Cutoff evidence
uses a cumulative successful-verdict counter, independent of event eviction.
The retained authorities cap event history at 10,000 entries and preserve their
virtual clock origin across a controlled refresh. Only the two new authority
containers were refreshed; all original services and all twelve new Arc process
identities, images, start times and restart counts stayed unchanged.

Raw first-cycle evidence is retained. Its duplicate governance insertions,
whole-table equality checks during pending replicated additions, and immediate
post-compaction candidate assumptions were harness defects. They were corrected
in test infrastructure, without changing production code. Original-stack
watchdogs recorded 155, 151 and 36 samples across the two cycles and focused
recheck, with no changes; before/after container identity checks also cover the
intervals between runs and authority refreshes.

Keep redacted summaries, per-stage reports, stack manifests, data audits and
protection snapshots outside the checkout. Private keys, tokens, env files,
databases and control credentials must never be included in published evidence.

Do not rerun initial setup against retained resources. Explicit `--resume`
requires a synthetic term date later than both authorities' effective current
time, validates the complete participant manifest, and renews only synthetic
grants without restarting Arc. The initial build uses `--extra-tls-ip
10.251.144.2 --extra-tls-ip 10.251.146.2` for verified private-IP control access.
There is no automatic stack stop/removal path.

Coverage limits: production activation/machine-cap refusal, successful OSS or
inverse handoff, Arc API/cluster TLS transport combinations, SSO, backup/restore,
edge sync, shared-storage multi-writer, multi-region and arcx execution were not
exercised. Commercial/support feature flags are entitlement metadata, not runtime
execution evidence. Original real-key natural-expiry observation continues
independently on its unchanged image.

## Suspension, reactivation and normalization

`normalization.py` reuses only the retained synthetic installations. Run from
an isolated worktree based on the test branch; never point it at real keys.
It requires the verified profile/node/fingerprint manifest, private synthetic
material and the original-service watchdog state. It does not change system time
or application code. Each invocation requires a new output directory.

```bash
python3 scripts/license_docker/normalization.py \
  --state /path/to/new-private-output \
  --fixture-state /path/to/three-stacks \
  --material /path/to/three-stack-material \
  --live-state /path/to/live
```

Use `--refresh-authority-image <fixture-image>` only to install the stateful
activation fixture on the two owned synthetic authorities; it preserves clock
origin, counters, IPs and profiles. It replaces those authority containers,
never the retained Arc containers. `--focused` rechecks the corrected failover
permission and eligible migration pause/resume oracles only. It omits the full
suspension/activation and suspended-startup cases.

Coverage includes definitive suspension and same-key reactivation for all three
profiles, machine activation missing/revoked recovery, temporary activation 503,
definitive activation suspension, request/cache continuity, per-key isolation,
existing RBAC enforcement, feature management, configuration/history retention,
new scheduled CQ output, retention data effects, audit events and tier migration.
Suspension is tested before expiration: no expiry grace is assumed for it.
A separate disposable Unlimited instance starts suspended with empty independent
storage; only that instance may be restarted and removed.

The first run (`09a73b83`) recorded **928 PASS / 19 FAIL / 1 OBSERVED**. Raw results
are retained unchanged. Fourteen failures were a test-oracle mistake: primary
monitoring also runs on Professional, without licensed automatic replacement.
Three failures were fixture eligibility gaps: off-state compaction did not
establish daily migration candidates. These are not product defects. The
corrected harness checks the explicit startup `auto_failover` permission and
prepares physical daily files plus a positive licensed dry-run before suspension;
missing eligibility is inconclusive. Actual writer crash/replacement is untested.

The remaining two failed assertions expose **one confirmed normalization defect**:
an instance booting during definitive suspension stays OSS after the server
reactivates its key. Its authority request count stayed at one verification over
six accelerated refresh intervals. `cmd/arc/main.go:348` discards the client;
periodic verification is started only for a non-nil client at `:2042–2043`.
Restarting only the disposable probe restored licensed access and retained its
five acknowledged records. This is a workaround, not automatic recovery.

Already-running installations recovered feature access automatically. Fresh CQ
output, retention deletion of old probe rows while retaining current rows, audit
events and automatic migration occurred after reactivation on all three profiles.
Finite acknowledged-ID sets, 30 original cold rows per profile, stable config
row hashes, completed histories and SQLite integrity were preserved. A token
created/rotated while suspended remained valid after reactivation, with the old
token refused. This tests retained clusters; these historical runs did not exercise a completed
OSS ownership handoff; use the lifecycle acceptance suite for that coverage.
Production activation service compatibility and machine-cap enforcement are also
outside this synthetic test.

These historical suspension runs used private external state directories.
Their redacted evidence must be reviewed separately from private runtime state.
The current production lifecycle implementation is exercised by
`lifecycle_runtime.py`.

The corrected focused run records **200 PASS / 0 FAIL**, including eligible
migration pause/resume on all three installations. Twenty local Python fixture
and harness regression tests pass. Authority state is saved to its actual bind
mount on reuse; refresh preflights the image and retains the old container and
network configuration for rollback until its replacement is verified healthy.
