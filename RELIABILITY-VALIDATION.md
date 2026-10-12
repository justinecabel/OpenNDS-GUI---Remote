# Manager freeze prevention validation

Validated 11 October 2026 against the deployed `app.py` SHA-256
`e4013df07d65fd43e3152fa9d98f5905b2e96423b33c99e03f7b1f6bd6665526`.

## Confirmed cause and prevention

The automatic network refresh held `_networks_lock` while waiting for
`_punishment_tc_lock`. A concurrent Punish queue update held the traffic-control
lock while reading network state. Neither could finish. Client polls then
occupied all eight request threads waiting for network state, preventing login
and other requests from running.

The deployed fix completes network-state publication and releases its lock
before reconciling queues. `_auth_control_lock` still serializes the complete
mode transition. Failed network attachment does not reconcile queues.

Preserve these rules when editing the manager:

- Never acquire the traffic-control lock while holding the network-state lock,
  including through a helper function. Queue updates may read network state.
- Keep `_sqm_settings_lock` before `_sqm_conditional_lock` when both are needed.
  Daily policy reconciliation can acquire the traffic-control lock afterward.
- Release accounting/cache locks before SSH or control operations. Preserve the
  separate control/telemetry SSH locks and the existing single background owner.
- Run the concurrent network-refresh/Punish regression and the full offline
  Python suite before deploying changes to these paths. Keep Gunicorn at one
  worker; extra threads only delay exhaustion if a deadlock returns.

## Evidence

- The new concurrency regression fails against the original deployed function.
  The corrected function passed 500 repeated two-thread interleavings with zero
  errors or failures. Events force the relevant overlap; this does not depend on
  hoping two operations happen at the same time.
- The full offline suite passed 191 Python tests and five dependency-free
  JavaScript checks during the fix deployment.
- Static call-graph inspection covered 217 module-level functions, 17 manager
  locks and 40 possible nested-lock dependencies, finding no remaining cycle.
  The scan excludes dynamically dispatched calls, nested callbacks and imported
  library locks; it is supporting evidence, not a proof against every hang.
- Read-only live checks cover concurrent login, Clients, Overview/history,
  Mode/QoS, manual network scans, Status and the periodic refresh interval.
  The initial recovery run completed 160 requests without failures, with fresh
  traffic/client data. Existing router sessions and SQM settings were preserved.
  A second validation run completed another 160 requests over 76 seconds with
  zero failures, median 18 ms, maximum 782 ms, fresh client/QoS snapshots and
  advancing WAN samples. Manager logs remained clean.
- No real-device Punish, mode or SQM policy was changed to provoke the fault.
  The destructive overlap was reproduced only with mocked router operations.

Inspection artifacts: `/tmp/opennds-hang-stacks.txt`,
`/tmp/opennds-lock-audit.json`, `/tmp/opennds-lock-audit.py`, and
`/tmp/opennds-recovery-results.json`.

Offline suite:

```sh
docker run --rm --network none \
  --mount 'type=bind,source=/home/justine/Data/Open NDS,target=/work,readonly' \
  -w /work opennds-opennds-manager:latest \
  python -B -m unittest discover -s tests
```

## Remaining recovery gap

There is currently no independent HTTP watchdog. The configured Gunicorn
gthread main loop sends `notify()` even when request threads are blocked; its
90-second timeout therefore did not detect this incident. The container stayed
running, so `restart: unless-stopped` had no exit to recover from.

Recommended additional protection is an independent HTTP probe with a bounded
timeout, repeated-failure threshold and restart backoff. It should capture
diagnostics and restart only the manager when HTTP remains unresponsive. A
router outage or stale traffic data alone should not cause restart loops. Probe
requests must remain read-only. This watchdog has not been added by this
validation task; preventing the identified deadlock and detecting/recovering
from a different future hang are separate protections.
