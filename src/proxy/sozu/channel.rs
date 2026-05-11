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
