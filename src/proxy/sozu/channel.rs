//! Low-level synchronous primitives for talking to a Sōzu worker over its
//! command channel: a readiness probe and a request/response correlator that
//! waits for the worker's ack on a given request ID.

use sozu_command_lib::{
    channel::Channel,
    proto::command::{
        Request, ResponseStatus, Status, WorkerRequest, WorkerResponse, request::RequestType,
    },
};
use std::time::Duration;
use tracing::{debug, error, info};

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
    let deadline = std::time::Instant::now() + Duration::from_millis(2000);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow::anyhow!(
                "Worker did not ack {} within 2s; configuration may be desynced",
                id
            ));
        }
        match channel.read_message_blocking_timeout(Some(remaining)) {
            Ok(response) => {
                if response.id == id {
                    if response.status == ResponseStatus::Failure as i32 {
                        error!("Worker rejected command {}: {}", id, response.message);
                        return Err(anyhow::anyhow!(
                            "Worker rejected {}: {}",
                            id,
                            response.message
                        ));
                    }
                    return Ok(());
                }
                // Not our response, keep reading
                debug!(
                    "Received response for {} while waiting for {}",
                    response.id, id
                );
            }
            Err(e) => {
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
}
