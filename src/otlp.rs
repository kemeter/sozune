//! OTLP exporters shared by tracing and metrics.
//!
//! Both signals reach their collector the same way: over gRPC or HTTP, with
//! optional headers, TLS (custom CA, client certificate) and extra resource
//! attributes. This module turns an [`OtlpExporterConfig`] into the span or
//! metric exporter of the chosen transport.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::tonic_types::metadata::MetadataMap;
use opentelemetry_otlp::tonic_types::transport::{Certificate, ClientTlsConfig, Identity};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;

use crate::config::{ClientTlsFiles, OtlpExporterConfig, OtlpProtocol};
use crate::util::client_tls::{client_identity, read_ca};

/// Same per-export timeout as the OTLP exporters' default.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// The signal an exporter carries, for the HTTP path (`/v1/traces`, …).
#[derive(Clone, Copy)]
pub enum Signal {
    Traces,
    Metrics,
}

impl Signal {
    fn http_path(self) -> &'static str {
        match self {
            Signal::Traces => "/v1/traces",
            Signal::Metrics => "/v1/metrics",
        }
    }
}

/// The resource of every exported span or metric: `service.name` plus the
/// configured attributes.
pub fn resource(service_name: &str, cfg: &OtlpExporterConfig) -> Resource {
    // `service_name` last, so a `service.name` among the attributes can't
    // override the dedicated setting.
    Resource::builder()
        .with_attributes(
            cfg.resource_attributes
                .iter()
                .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
        )
        .with_service_name(service_name.to_string())
        .build()
}

pub fn span_exporter(
    endpoint: &str,
    cfg: &OtlpExporterConfig,
) -> anyhow::Result<opentelemetry_otlp::SpanExporter> {
    let builder = opentelemetry_otlp::SpanExporter::builder();
    let exporter = match cfg.protocol {
        OtlpProtocol::Grpc => grpc(builder.with_tonic(), endpoint, cfg)?.build()?,
        OtlpProtocol::Http => http(builder.with_http(), endpoint, Signal::Traces, cfg)?.build()?,
    };
    Ok(exporter)
}

pub fn metric_exporter(
    endpoint: &str,
    cfg: &OtlpExporterConfig,
) -> anyhow::Result<opentelemetry_otlp::MetricExporter> {
    let builder = opentelemetry_otlp::MetricExporter::builder();
    let exporter = match cfg.protocol {
        OtlpProtocol::Grpc => grpc(builder.with_tonic(), endpoint, cfg)?.build()?,
        OtlpProtocol::Http => http(builder.with_http(), endpoint, Signal::Metrics, cfg)?.build()?,
    };
    Ok(exporter)
}

/// Endpoint, headers and, on an `https://` endpoint, TLS of a gRPC export.
fn grpc<B: WithExportConfig + WithTonicConfig>(
    builder: B,
    endpoint: &str,
    cfg: &OtlpExporterConfig,
) -> anyhow::Result<B> {
    check_tls_scheme(endpoint, &cfg.tls)?;
    let builder = builder
        .with_protocol(Protocol::Grpc)
        .with_endpoint(endpoint.to_string())
        .with_metadata(MetadataMap::from_headers(header_map(&cfg.headers)?));
    if endpoint.starts_with("https://") {
        Ok(builder.with_tls_config(grpc_tls(&cfg.tls)?))
    } else {
        Ok(builder)
    }
}

/// Endpoint, headers and HTTP client of an HTTP export.
fn http<B: WithExportConfig + WithHttpConfig>(
    builder: B,
    endpoint: &str,
    signal: Signal,
    cfg: &OtlpExporterConfig,
) -> anyhow::Result<B> {
    let endpoint = http_endpoint(endpoint, signal)?;
    check_tls_scheme(&endpoint, &cfg.tls)?;
    let headers = header_map(&cfg.headers)?
        .iter()
        // The builder URL-decodes header values; escaping `%` makes it hand
        // back the configured value unchanged.
        .map(|(k, v)| Ok((k.to_string(), v.to_str()?.replace('%', "%25"))))
        .collect::<anyhow::Result<HashMap<String, String>>>()?;
    Ok(builder
        // Set explicitly so `OTEL_EXPORTER_OTLP_PROTOCOL` can't override it.
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .with_headers(headers)
        .with_http_client(http_client(&cfg.tls)?))
}

/// TLS settings are only honoured on an `https://` endpoint; on a plain one
/// they would be silently ignored and the export sent in the clear.
fn check_tls_scheme(endpoint: &str, tls: &ClientTlsFiles) -> anyhow::Result<()> {
    let tls_set = tls.ca.is_some() || tls.cert.is_some() || tls.key.is_some();
    if tls_set && !endpoint.starts_with("https://") {
        anyhow::bail!("OTLP TLS settings need an https:// endpoint, got {endpoint}");
    }
    Ok(())
}

/// The URL an HTTP export is sent to. An endpoint without a path gets the
/// signal's (`/v1/traces`, `/v1/metrics`), so `http://collector:4318` is
/// enough. An endpoint with a path is kept as is.
fn http_endpoint(endpoint: &str, signal: Signal) -> anyhow::Result<String> {
    let mut url =
        url::Url::parse(endpoint).with_context(|| format!("invalid OTLP endpoint `{endpoint}`"))?;
    if url.path() == "/" {
        url.set_path(signal.http_path());
    }
    Ok(url.to_string())
}

/// The configured headers, validated: an invalid name or value is an error
/// rather than a header silently dropped. Names are lowercased, as gRPC
/// requires (HTTP header names are case-insensitive).
fn header_map(
    headers: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<axum::http::HeaderMap> {
    let mut map = axum::http::HeaderMap::new();
    for (key, value) in headers {
        let name = axum::http::HeaderName::from_bytes(key.to_lowercase().as_bytes())
            .with_context(|| format!("invalid OTLP header name `{key}`"))?;
        if !value.is_ascii() {
            anyhow::bail!("invalid value for OTLP header `{key}`: only ASCII is allowed");
        }
        let value = axum::http::HeaderValue::from_str(value)
            .with_context(|| format!("invalid value for OTLP header `{key}`"))?;
        map.insert(name, value);
    }
    Ok(map)
}

/// TLS of a gRPC export: the system and web PKI roots plus `tls.ca`, and the client
/// certificate when one is set.
fn grpc_tls(tls: &ClientTlsFiles) -> anyhow::Result<ClientTlsConfig> {
    let mut config = ClientTlsConfig::new().with_webpki_roots();
    // Tonic refuses to connect when asked for an empty system store (a minimal
    // image without CA certificates); the web PKI roots and `tls.ca` then
    // carry the trust alone.
    if !crate::util::http_client::system_store_is_empty() {
        config = config.with_native_roots();
    }
    if let Some(ca) = &tls.ca {
        config = config.ca_certificate(Certificate::from_pem(read_ca(ca)?));
    }
    if let Some((cert, key)) = client_identity(tls)? {
        config = config.identity(Identity::from_pem(cert, key));
    }
    Ok(config)
}

/// The blocking HTTP client of an HTTP export, with `tls.ca` trusted and the
/// client certificate when one is set. Built on its own thread: a blocking
/// client must not be created inside the async runtime.
fn http_client(tls: &ClientTlsFiles) -> anyhow::Result<reqwest::blocking::Client> {
    let ca = match &tls.ca {
        Some(path) => Some(read_ca(path)?),
        None => None,
    };
    let identity = client_identity(tls)?;
    std::thread::spawn(move || -> anyhow::Result<reqwest::blocking::Client> {
        let mut builder = crate::util::http_client::blocking_builder().timeout(EXPORT_TIMEOUT);
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&ca).context("invalid PEM in tls.ca")?,
            );
        }
        if let Some((mut cert, key)) = identity {
            cert.push(b'\n');
            cert.extend_from_slice(&key);
            builder = builder.identity(
                reqwest::Identity::from_pem(&cert).context("invalid PEM in tls.cert or tls.key")?,
            );
        }
        Ok(builder.build()?)
    })
    .join()
    .map_err(|_| anyhow::anyhow!("building the OTLP HTTP client panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn http_endpoint_gets_the_signal_path() {
        assert_eq!(
            http_endpoint("http://127.0.0.1:4318", Signal::Traces).unwrap(),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(
            http_endpoint("http://127.0.0.1:4318", Signal::Metrics).unwrap(),
            "http://127.0.0.1:4318/v1/metrics"
        );
    }

    #[test]
    fn http_endpoint_without_path_gets_the_signal_path() {
        assert_eq!(
            http_endpoint("https://otlp.example.com", Signal::Metrics).unwrap(),
            "https://otlp.example.com/v1/metrics"
        );
        assert_eq!(
            http_endpoint("https://otlp.example.com/", Signal::Traces).unwrap(),
            "https://otlp.example.com/v1/traces"
        );
    }

    #[test]
    fn http_endpoint_with_a_path_is_kept() {
        assert_eq!(
            http_endpoint("https://otlp.example.com/otlp/v1/traces", Signal::Traces).unwrap(),
            "https://otlp.example.com/otlp/v1/traces"
        );
    }

    #[test]
    fn http_endpoint_with_a_trailing_slash_path_is_kept() {
        assert_eq!(
            http_endpoint("https://otlp.example.com/otlp/", Signal::Traces).unwrap(),
            "https://otlp.example.com/otlp/"
        );
    }

    #[test]
    fn http_endpoint_keeps_the_query() {
        assert_eq!(
            http_endpoint("https://otlp.example.com?tenant=a", Signal::Metrics).unwrap(),
            "https://otlp.example.com/v1/metrics?tenant=a"
        );
    }

    #[test]
    fn non_ascii_header_value_is_an_error() {
        let headers = BTreeMap::from([("x-api-key".to_string(), "clé".to_string())]);
        let err = header_map(&headers).unwrap_err().to_string();
        assert!(err.contains("ASCII"), "{err}");
    }

    #[test]
    fn ca_without_a_certificate_is_an_error() {
        let file = std::env::temp_dir().join(format!("sozune-empty-ca-{}.pem", std::process::id()));
        std::fs::write(&file, "not a certificate\n").unwrap();
        let err = read_ca(file.to_str().unwrap()).unwrap_err().to_string();
        std::fs::remove_file(&file).unwrap();
        assert!(err.contains("no PEM certificate"), "{err}");
    }

    #[test]
    fn ca_with_an_invalid_certificate_is_an_error() {
        let file = std::env::temp_dir().join(format!("sozune-bad-ca-{}.pem", std::process::id()));
        std::fs::write(
            &file,
            "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let err = read_ca(file.to_str().unwrap()).unwrap_err().to_string();
        std::fs::remove_file(&file).unwrap();
        assert!(err.contains("not a valid CA"), "{err}");
    }

    #[test]
    fn header_names_are_lowercased() {
        let headers = BTreeMap::from([("X-Api-Key".to_string(), "secret".to_string())]);
        let map = header_map(&headers).unwrap();
        assert_eq!(map.get("x-api-key").unwrap(), "secret");
    }

    #[test]
    fn invalid_header_is_an_error_on_both_protocols() {
        for protocol in [OtlpProtocol::Grpc, OtlpProtocol::Http] {
            let cfg = OtlpExporterConfig {
                protocol,
                headers: BTreeMap::from([("bad header".to_string(), "v".to_string())]),
                ..Default::default()
            };
            assert!(metric_exporter("http://127.0.0.1:4317", &cfg).is_err());
        }
    }

    #[test]
    fn cert_without_key_is_an_error() {
        let tls = ClientTlsFiles {
            cert: Some("/nonexistent.pem".to_string()),
            ..Default::default()
        };
        let err = client_identity(&tls).unwrap_err().to_string();
        assert!(err.contains("together"), "{err}");
    }

    #[test]
    fn tls_settings_on_a_plain_endpoint_are_an_error_on_both_protocols() {
        for protocol in [OtlpProtocol::Grpc, OtlpProtocol::Http] {
            let cfg = OtlpExporterConfig {
                protocol,
                tls: ClientTlsFiles {
                    ca: Some("/ca.pem".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            };
            let err = span_exporter("http://collector:4317", &cfg)
                .unwrap_err()
                .to_string();
            assert!(err.contains("https://"), "{err}");
        }
    }

    #[test]
    fn resource_carries_the_extra_attributes() {
        let cfg = OtlpExporterConfig {
            resource_attributes: BTreeMap::from([
                ("deployment.environment".to_string(), "prod".to_string()),
                ("service.name".to_string(), "other".to_string()),
            ]),
            ..Default::default()
        };
        let resource = resource("sozune", &cfg);
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str(
                    "deployment.environment"
                ))
                .map(|v| v.to_string()),
            Some("prod".to_string())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.name"))
                .map(|v| v.to_string()),
            Some("sozune".to_string())
        );
    }
}
