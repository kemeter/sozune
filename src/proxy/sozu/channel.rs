//! Low-level synchronous primitives for talking to a Sōzu worker over its
//! command channel: a readiness probe and a request/response correlator that
//! waits for the worker's ack on a given request ID.

use sozu_command_lib::{
    channel::Channel,
    proto::command::{
        Request, ResponseStatus, Status, WorkerRequest, WorkerResponse, request::RequestType,
    },
};
use std::cell::Cell;
use std::time::Duration;
use tracing::{debug, error, info};

/// Per-command deadline for a worker ack. Long enough that a healthy worker
/// (which answers in single-digit ms) is never cut off.
const PER_COMMAND_TIMEOUT: Duration = Duration::from_millis(2000);

/// How many *consecutive* command timeouts mark a worker as unresponsive. Once
/// reached, the rest of the reload fails fast instead of each command blocking
/// for `PER_COMMAND_TIMEOUT`. A worker that keeps acking (even on a large, slow
/// reload of many entrypoints) never trips this, because every successful ack
/// resets the counter — only a genuinely silent worker accumulates failures.
const MAX_CONSECUTIVE_TIMEOUTS: u32 = 3;

thread_local! {
    /// Number of consecutive `send_to_worker` timeouts within the reload in
    /// flight. `None` outside a reload (standalone calls are never short-circuited).
    /// Counts timeouts, not wall-clock: a big healthy reload is unaffected, but a
    /// silent worker is cut off after `MAX_CONSECUTIVE_TIMEOUTS` instead of
    /// freezing the event loop for `PER_COMMAND_TIMEOUT × command count`
    /// (see issues/send-to-worker-blocking-stalls-reload.md).
    static CONSECUTIVE_TIMEOUTS: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Run `f` as a reload: `send_to_worker` calls it triggers share a consecutive
/// -timeout counter, so once a worker is shown unresponsive the remaining
/// commands fail fast. Restores any previous state on the way out (reloads don't
/// nest today, but this keeps the guard panic-safe).
pub(super) fn with_reload_budget<T>(f: impl FnOnce() -> T) -> T {
    let previous = CONSECUTIVE_TIMEOUTS.replace(Some(0));
    let _restore = RestoreCounter(previous);
    f()
}

struct RestoreCounter(Option<u32>);

impl Drop for RestoreCounter {
    fn drop(&mut self) {
        CONSECUTIVE_TIMEOUTS.set(self.0);
    }
}

/// Whether the current reload has already given up on the worker (too many
/// consecutive timeouts). Always `false` outside a reload.
fn worker_given_up() -> bool {
    matches!(CONSECUTIVE_TIMEOUTS.get(), Some(n) if n >= MAX_CONSECUTIVE_TIMEOUTS)
}

/// Record the outcome of a command so the consecutive-timeout counter tracks the
/// worker's responsiveness. A success resets it; a timeout increments it.
fn record_command_outcome(timed_out: bool) {
    if let Some(n) = CONSECUTIVE_TIMEOUTS.get() {
        CONSECUTIVE_TIMEOUTS.set(Some(if timed_out { n + 1 } else { 0 }));
    }
}

pub(super) fn wait_for_worker_ready(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    channel.write_message(&WorkerRequest {
        id: format!("{}-readiness-probe", name),
        content: Request {
            request_type: Some(RequestType::Status(Status {})),
        },
    })?;

    match channel.read_message_blocking_timeout(Some(timeout)) {
        Ok(_) => {
            info!("{} worker is ready", name);
            Ok(())
        }
        Err(e) => {
            anyhow::bail!(
                "{} worker failed to become ready within {:?}: {}",
                name,
                timeout,
                e
            );
        }
    }
}

pub(super) fn send_to_worker(
    channel: &mut Channel<WorkerRequest, WorkerResponse>,
    id: String,
    request: RequestType,
) -> anyhow::Result<()> {
    channel.write_message(&WorkerRequest {
        id: id.clone(),
        content: Request {
            request_type: Some(request),
        },
    })?;

    // Read responses until we find the one matching our request ID. Bailing
    // out with `Ok(())` on timeout or channel error would leave the caller
    // believing the worker accepted the command while it may have rejected,
    // queued, or never received it — that silent drift caused entrypoint
    // desync against the live worker in the past. Return the actual failure.
    //
    // Within a reload, if the worker has already timed out on
    // `MAX_CONSECUTIVE_TIMEOUTS` commands in a row it is treated as unresponsive
    // and the rest of the reload fails fast — re-waiting the full timeout for
    // every remaining command is what froze the event loop. A reload of many
    // healthy (if slow) entrypoints is unaffected: each ack resets the counter.
    if worker_given_up() {
        return Err(anyhow::anyhow!(
            "Worker did not ack {}; gave up after {} consecutive timeouts (worker unresponsive)",
            id,
            MAX_CONSECUTIVE_TIMEOUTS
        ));
    }

    let deadline = std::time::Instant::now() + PER_COMMAND_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            record_command_outcome(true);
            return Err(anyhow::anyhow!(
                "Worker did not ack {} within {:?}; configuration may be desynced",
                id,
                PER_COMMAND_TIMEOUT
            ));
        }
        match channel.read_message_blocking_timeout(Some(remaining)) {
            Ok(response) => {
                if response.id == id {
                    if response.status == ResponseStatus::Failure as i32 {
                        error!("Worker rejected command {}: {}", id, response.message);
                        // A rejection means the worker answered, so it is
                        // responsive — reset the timeout streak.
                        record_command_outcome(false);
                        return Err(anyhow::anyhow!(
                            "Worker rejected {}: {}",
                            id,
                            response.message
                        ));
                    }
                    record_command_outcome(false);
                    return Ok(());
                }
                // Not our response, keep reading
                debug!(
                    "Received response for {} while waiting for {}",
                    response.id, id
                );
            }
            Err(e) => {
                // The blocking read consumed its timeout (or the channel
                // errored) without an ack. Either way the worker did not answer,
                // so count it toward the consecutive-timeout streak: a silent
                // worker surfaces here as `TimeoutReached`, and this is what lets
                // the reload give up instead of re-blocking on every command.
                record_command_outcome(true);
                return Err(anyhow::anyhow!(
                    "Channel error while waiting for ack of {}: {}",
                    id,
                    e
                ));
            }
        }
    }
}

#[cfg(test)]
mod repro_tests {
    //! Reproduction harness for the production incident where Sōzune froze all
    //! traffic. These tests drive the *real* `Channel::generate(1000, 10000)`
    //! pair (same buffer sizes as production) to observe, not assume, what the
    //! command channel does when (a) a worker reply exceeds the 10000-byte back
    //! buffer and (b) a worker stays silent. The goal is to confirm the root
    //! cause before any fix is written.

    use super::*;
    use crate::config::{default_command_buffer_max_bytes, default_metrics_poll_timeout_ms};
    use std::time::Instant;

    /// (a) A reply larger than `max_buffer_size` (10000 bytes, the prod value)
    /// surfaces the exact "too large for back buffer capacity" error we saw in
    /// production — observed to be raised on the WORKER's WRITE, not on
    /// Sōzune's read. The oversized frame never leaves the worker, so from
    /// Sōzune's side the worker simply goes silent (see test b for the freeze
    /// this silence then causes).
    #[test]
    fn oversized_worker_reply_fails_on_worker_write_with_back_buffer_error() {
        let (_command, mut proxy) = Channel::<WorkerRequest, WorkerResponse>::generate(1000, 10000)
            .expect("generate channel pair");
        // The proxy-side channel is the worker's view; blocking so the write
        // path mirrors a real worker emitting its reply.
        proxy.blocking().expect("set proxy side blocking");

        // A reply whose serialized size exceeds 10000 bytes by stuffing the
        // `message` field — mirrors a fat WorkerMetrics payload growing past the
        // ceiling as entrypoints accumulate. 12_000 bytes -> message_len 12033.
        let huge = WorkerResponse {
            id: "HTTP-metrics-repro".to_string(),
            status: ResponseStatus::Ok as i32,
            message: "x".repeat(12_000),
            content: None,
        };

        let err = proxy
            .write_message(&huge)
            .expect_err("oversized reply must be rejected by the channel");
        let msg = err.to_string();
        println!("[repro a] worker write error = {msg}");

        // Confirm it is the exact production error.
        assert!(
            msg.contains("too large for back buffer capacity"),
            "expected back-buffer-capacity error, got: {msg}"
        );
    }

    /// (b) A silent worker makes the blocking read consume its entire deadline.
    /// poll_worker_metrics calls this for BOTH workers, so a 2000ms deadline
    /// means up to ~4s of frozen select! loop per poll cycle.
    #[test]
    fn silent_worker_burns_the_full_blocking_deadline() {
        let (mut command, _proxy) = Channel::<WorkerRequest, WorkerResponse>::generate(1000, 10000)
            .expect("generate channel pair");
        // _proxy stays alive but never replies.

        let started = Instant::now();
        let result = command.read_message_blocking_timeout(Some(Duration::from_millis(2000)));
        let elapsed = started.elapsed();
        println!("[repro b] elapsed={elapsed:?} result={result:?}");

        assert!(result.is_err(), "silent worker must time out");
        assert!(
            elapsed >= Duration::from_millis(1900),
            "expected ~2s blocking wait, got {elapsed:?}"
        );
    }

    /// Regression guard for the freeze fix: with the *default* metrics poll
    /// timeout, a silent worker must release the loop quickly (well under the
    /// old 2s), so a metrics hiccup can never monopolize the proxying loop.
    /// Mirrors the read poll_worker_metrics performs, bounded by the config
    /// default. Fails fast if anyone restores a multi-second deadline.
    #[test]
    fn default_poll_timeout_bounds_a_silent_worker_to_well_under_two_seconds() {
        let default_ms = default_metrics_poll_timeout_ms();
        assert!(
            default_ms <= 500,
            "default metrics poll timeout regressed to {default_ms}ms; \
             a long blocking deadline re-introduces the freeze"
        );

        let (mut command, _proxy) = Channel::<WorkerRequest, WorkerResponse>::generate(1000, 10000)
            .expect("generate channel pair");

        let started = Instant::now();
        let result = command.read_message_blocking_timeout(Some(Duration::from_millis(default_ms)));
        let elapsed = started.elapsed();
        println!("[regression] default={default_ms}ms elapsed={elapsed:?} result={result:?}");

        assert!(result.is_err(), "silent worker must still time out");
        // The blocking read has a 100ms internal poll granularity, so allow a
        // little slack above the deadline, but it must stay far below the old 2s.
        assert!(
            elapsed < Duration::from_millis(800),
            "poll did not release the loop fast enough: {elapsed:?}"
        );
    }

    /// With the raised default ceiling, a reply that overflowed the old
    /// 10000-byte buffer (the prod incident) now fits and round-trips cleanly.
    /// Pairs with repro (a): same 12_000-byte payload, but written and read back
    /// successfully instead of being rejected.
    #[test]
    fn raised_ceiling_lets_a_formerly_oversized_reply_round_trip() {
        let max = default_command_buffer_max_bytes();
        assert!(
            max > 10_000,
            "ceiling must exceed the old 10000-byte limit, got {max}"
        );

        let (mut command, mut proxy) =
            Channel::<WorkerRequest, WorkerResponse>::generate(1000, max)
                .expect("generate channel pair");
        proxy.blocking().expect("set proxy side blocking");

        let reply = WorkerResponse {
            id: "HTTP-metrics-repro".to_string(),
            status: ResponseStatus::Ok as i32,
            message: "x".repeat(12_000),
            content: None,
        };
        proxy
            .write_message(&reply)
            .expect("reply now fits under the raised ceiling");

        let got = command
            .read_message_blocking_timeout(Some(Duration::from_millis(500)))
            .expect("reply round-trips under the raised ceiling");
        assert_eq!(got.id, "HTTP-metrics-repro");
        assert_eq!(got.message.len(), 12_000);
    }

    /// Reproduces the *cumulative* stall risk of config application. A reload
    /// issues many `send_to_worker` commands back-to-back; each blocks up to its
    /// deadline waiting for the worker ack. If the worker goes silent mid-reload,
    /// the stalls add up: N commands × per-command deadline. This proves the
    /// mechanism with a tiny deadline so it stays fast — at the real 2s deadline
    /// the same 8 commands would freeze the reload loop for ~16s.
    #[test]
    fn sequential_commands_to_a_silent_worker_accumulate_stalls() {
        let (mut command, _proxy) = Channel::<WorkerRequest, WorkerResponse>::generate(1000, 10000)
            .expect("generate channel pair");
        // _proxy never replies — every command will time out.

        let per_command = Duration::from_millis(50);
        let commands = 8;

        let started = Instant::now();
        let mut timeouts = 0;
        for _ in 0..commands {
            // Mirror send_to_worker's read: a bounded blocking wait for the ack.
            if command
                .read_message_blocking_timeout(Some(per_command))
                .is_err()
            {
                timeouts += 1;
            }
        }
        let elapsed = started.elapsed();
        println!("[stall] {commands} commands, {timeouts} timeouts, elapsed={elapsed:?}");

        assert_eq!(
            timeouts, commands,
            "a silent worker times out every command"
        );
        // The cost is N × per_command, NOT a single deadline — that linear
        // accumulation is the bug a global reload budget must cap.
        assert!(
            elapsed >= per_command * commands,
            "stalls must accumulate linearly, got {elapsed:?}"
        );
    }

    /// The fix: under `with_reload_budget`, a flood of commands to a silent
    /// worker is short-circuited after `MAX_CONSECUTIVE_TIMEOUTS` failures, so
    /// the total stall is bounded by that constant (× PER_COMMAND_TIMEOUT), NOT
    /// by the number of commands. The remaining commands fail fast.
    #[test]
    fn reload_budget_caps_total_stall_on_a_silent_worker() {
        let (mut command, _proxy) = Channel::<WorkerRequest, WorkerResponse>::generate(1000, 10000)
            .expect("generate channel pair");

        let commands = 50;
        let mut fast_fails = 0;
        let started = Instant::now();
        with_reload_budget(|| {
            for i in 0..commands {
                let before = Instant::now();
                let r = send_to_worker(
                    &mut command,
                    format!("probe-{i}"),
                    RequestType::Status(Status {}),
                );
                assert!(r.is_err(), "silent worker must never ack");
                // After the worker is given up on, commands return ~instantly
                // instead of blocking for PER_COMMAND_TIMEOUT.
                if before.elapsed() < Duration::from_millis(50) {
                    fast_fails += 1;
                }
            }
        });
        let elapsed = started.elapsed();
        println!("[budget] {commands} commands, {fast_fails} fast-failed, elapsed={elapsed:?}");

        // Only the first MAX_CONSECUTIVE_TIMEOUTS commands actually block; the
        // rest fail fast. Total stall ~= MAX_CONSECUTIVE_TIMEOUTS × 2s, NOT
        // 50 × 2s = 100s.
        assert!(
            elapsed < PER_COMMAND_TIMEOUT * (MAX_CONSECUTIVE_TIMEOUTS + 2),
            "stall must be bounded by the timeout streak, got {elapsed:?}"
        );
        assert!(
            fast_fails >= (commands - MAX_CONSECUTIVE_TIMEOUTS as usize - 1),
            "most commands must fail fast after the worker is given up on, got {fast_fails}"
        );
    }

    /// Regression guard for the prod incident this fix *caused* on first attempt:
    /// a large but HEALTHY reload (worker acks every command, even slowly) must
    /// NOT be short-circuited. Every ack resets the streak, so the counter never
    /// reaches MAX_CONSECUTIVE_TIMEOUTS and all commands go through.
    #[test]
    fn healthy_reload_is_never_short_circuited_however_large() {
        let (mut command, mut proxy) =
            Channel::<WorkerRequest, WorkerResponse>::generate(1000, 10000)
                .expect("generate channel pair");
        proxy.blocking().expect("set proxy side blocking");

        let commands = 200;
        let mut ok = 0;
        with_reload_budget(|| {
            for i in 0..commands {
                let id = format!("cmd-{i}");
                // Worker acks promptly before we send (pre-queued reply with the
                // matching id), so send_to_worker always succeeds.
                proxy
                    .write_message(&WorkerResponse {
                        id: id.clone(),
                        status: ResponseStatus::Ok as i32,
                        message: String::new(),
                        content: None,
                    })
                    .expect("worker acks");
                let r = send_to_worker(&mut command, id, RequestType::Status(Status {}));
                assert!(r.is_ok(), "healthy ack must succeed at command {i}");
                ok += 1;
            }
        });

        assert_eq!(
            ok, commands,
            "every command in a healthy reload must go through"
        );
    }

    /// Without a reload active (a standalone command), `send_to_worker` keeps its
    /// full per-command deadline — the streak counter only applies inside
    /// `with_reload_budget`, so non-reload callers are unaffected.
    #[test]
    fn standalone_command_keeps_full_per_command_timeout() {
        let (mut command, _proxy) = Channel::<WorkerRequest, WorkerResponse>::generate(1000, 10000)
            .expect("generate channel pair");

        let started = Instant::now();
        let r = send_to_worker(
            &mut command,
            "solo".to_string(),
            RequestType::Status(Status {}),
        );
        let elapsed = started.elapsed();

        assert!(r.is_err(), "silent worker times out");
        // No reload => full PER_COMMAND_TIMEOUT (2s). Confirm it waited, i.e. it
        // did not inherit a leaked counter from another test.
        assert!(
            elapsed >= Duration::from_millis(1900),
            "standalone command should wait the full timeout, got {elapsed:?}"
        );
    }
}
