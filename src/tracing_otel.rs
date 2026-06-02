//! OpenTelemetry distributed-tracing pipeline.
//!
//! When `tracing.enabled`, this builds an OTLP/gRPC span exporter, wires it
//! into an [`SdkTracerProvider`] with a configurable sampler, installs the W3C
//! `TraceContextPropagator` as the global propagator, and returns a
//! `tracing_subscriber` layer that turns every `tracing` span into an
//! OpenTelemetry span. The proxy handler opens one span per request (see
//! `middleware::proxy`), so each proxied request becomes a trace that a
//! collector (Jaeger, Tempo, Zipkin, …) can display.
//!
//! Spans are batch-exported on the Tokio runtime. [`TracingGuard`] holds the
//! provider so the caller can flush on shutdown — dropping it without a flush
//! would lose the last, unexported batch.

use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing::error;

use crate::config::TracingConfig;

/// Adapts an `axum::http::HeaderMap` so the W3C propagator can read incoming
/// `traceparent`/`tracestate` headers.
pub struct HeaderExtractor<'a>(pub &'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Adapts an `axum::http::HeaderMap` so the W3C propagator can write the outgoing
/// `traceparent`/`tracestate` headers toward the backend.
pub struct HeaderInjector<'a>(pub &'a mut axum::http::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(val)) = (
            axum::http::header::HeaderName::from_bytes(key.as_bytes()),
            axum::http::header::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, val);
        }
    }
}

/// Extract a remote span context from incoming request headers using the
/// globally-installed W3C propagator. Returns the otel `Context` to attach as
/// the parent of the request span.
pub fn extract_parent(headers: &axum::http::HeaderMap) -> opentelemetry::Context {
    opentelemetry::global::get_text_map_propagator(|prop| prop.extract(&HeaderExtractor(headers)))
}

/// Inject the given span context into outgoing headers as `traceparent`
/// (W3C), so the backend continues the same trace.
pub fn inject_context(cx: &opentelemetry::Context, headers: &mut axum::http::HeaderMap) {
    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.inject_context(cx, &mut HeaderInjector(headers));
    });
}

/// Keeps the tracer provider alive for the process lifetime and flushes
/// pending spans on shutdown. Drop (or call [`TracingGuard::shutdown`]) to
/// force-flush the last batch.
pub struct TracingGuard {
    provider: SdkTracerProvider,
}

impl TracingGuard {
    /// Flush and stop the exporter. Safe to call once; idempotent enough for
    /// a shutdown path.
    pub fn shutdown(&self) {
        if let Err(e) = self.provider.shutdown() {
            error!("tracing: failed to flush spans on shutdown: {e}");
        }
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Parse the `sampler` config string into an OpenTelemetry [`Sampler`].
///
/// - `parent_based_always_on` (default): follow the upstream decision, else
///   sample. The right default for a proxy — if the caller is tracing, we are.
/// - `always_on` / `always_off`: force the decision.
/// - `ratio:<0..1>`: parent-based ratio sampler, e.g. `ratio:0.1` = 10%.
///
/// An unrecognised value falls back to parent-based-always-on and logs once.
fn parse_sampler(spec: &str) -> Sampler {
    match spec.trim().to_ascii_lowercase().as_str() {
        "always_on" => Sampler::AlwaysOn,
        "always_off" => Sampler::AlwaysOff,
        "parent_based_always_on" => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
        "parent_based_always_off" => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
        other => {
            if let Some(rest) = other.strip_prefix("ratio:")
                && let Ok(r) = rest.parse::<f64>()
            {
                let r = r.clamp(0.0, 1.0);
                return Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(r)));
            }
            error!("tracing: unknown sampler '{spec}', using parent_based_always_on");
            Sampler::ParentBased(Box::new(Sampler::AlwaysOn))
        }
    }
}

/// Build the OTLP tracing pipeline and return `(layer, guard)`.
///
/// The layer must be added to the `tracing_subscriber` registry; the guard
/// must be kept alive for the process and flushed on shutdown. Returns `Err`
/// if the OTLP exporter can't be built (bad endpoint, etc.) so the caller can
/// fall back to logs-only rather than crash.
pub fn build_layer<S>(
    cfg: &TracingConfig,
) -> anyhow::Result<(
    tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>,
    TracingGuard,
)>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    // W3C Trace Context propagation, both directions (extract incoming
    // `traceparent`, inject outgoing).
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(cfg.endpoint.clone())
        .build()?;

    let resource = Resource::builder()
        .with_service_name(cfg.service_name.clone())
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(parse_sampler(&cfg.sampler))
        .with_resource(resource)
        .build();

    let tracer = provider.tracer("sozune");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    Ok((layer, TracingGuard { provider }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampler_parsing() {
        assert!(matches!(parse_sampler("always_on"), Sampler::AlwaysOn));
        assert!(matches!(parse_sampler("always_off"), Sampler::AlwaysOff));
        assert!(matches!(
            parse_sampler("parent_based_always_on"),
            Sampler::ParentBased(_)
        ));
        assert!(matches!(
            parse_sampler("ratio:0.1"),
            Sampler::ParentBased(_)
        ));
        // Unknown → parent-based fallback.
        assert!(matches!(parse_sampler("nonsense"), Sampler::ParentBased(_)));
    }

    #[test]
    fn ratio_out_of_range_is_clamped_not_panicking() {
        // Just must not panic; clamping happens internally.
        let _ = parse_sampler("ratio:5.0");
        let _ = parse_sampler("ratio:-1");
    }

    #[test]
    fn w3c_traceparent_round_trips_through_extract_and_inject() {
        use opentelemetry::trace::TraceContextExt;

        // Install the W3C propagator (idempotent across tests).
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

        // A valid, sampled W3C traceparent: version-traceid-spanid-flags.
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let span_id = "b7ad6b7169203331";
        let mut incoming = axum::http::HeaderMap::new();
        incoming.insert(
            "traceparent",
            format!("00-{trace_id}-{span_id}-01").parse().unwrap(),
        );

        // Extract the remote context, then inject it into a fresh header map.
        let cx = extract_parent(&incoming);
        assert!(
            cx.span().span_context().is_valid(),
            "extracted context must be a valid span"
        );
        assert_eq!(cx.span().span_context().trace_id().to_string(), trace_id);

        let mut outgoing = axum::http::HeaderMap::new();
        inject_context(&cx, &mut outgoing);

        // The propagated traceparent must carry the SAME trace id (the span id
        // changes — the parent of the next hop — but the trace is continuous).
        let tp = outgoing
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent injected");
        assert!(
            tp.contains(trace_id),
            "outgoing traceparent {tp} must keep trace id {trace_id}"
        );
    }
}
