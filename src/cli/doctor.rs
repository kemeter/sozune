use std::fmt::Write;
use std::path::Path;

use clap::Args;

use crate::config::AppConfig;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Skip checks that reach providers (sockets, HTTP endpoints, kubeconfig).
    #[arg(long)]
    pub offline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

struct CheckResult {
    category: &'static str,
    title: String,
    status: Status,
    detail: Option<String>,
    fix: Option<String>,
}

impl CheckResult {
    fn ok(category: &'static str, title: impl Into<String>) -> Self {
        Self {
            category,
            title: title.into(),
            status: Status::Ok,
            detail: None,
            fix: None,
        }
    }
    fn warn(category: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            category,
            title: title.into(),
            status: Status::Warn,
            detail: Some(detail.into()),
            fix: None,
        }
    }
    fn fail(category: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            category,
            title: title.into(),
            status: Status::Fail,
            detail: Some(detail.into()),
            fix: None,
        }
    }
    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

pub async fn run(args: DoctorArgs, config_path: &str) -> i32 {
    let mut results = Vec::new();

    // 1. Config file
    let config = match check_config(config_path, &mut results).await {
        Some(c) => c,
        None => {
            print_results(&results);
            return exit_code(&results);
        }
    };

    // 2. Ports: two listeners on one port never start, whatever the host
    // state. Probing the binds only makes sense while sozune is stopped:
    // a running instance holds every one of them.
    let listeners = collect_listeners(&config, &mut results);
    check_port_conflicts(&listeners, &mut results);
    if sozune_is_running(&config).await {
        results.push(CheckResult::ok(
            "instance",
            "sozune is running (the API answered /health), bind checks skipped",
        ));
    } else {
        for listener in &listeners {
            check_bind(listener, &mut results).await;
        }
    }

    // 3. ACME
    check_acme(&config, &mut results);

    // 4. Providers (network checks, skipped in --offline)
    if !args.offline {
        check_providers(&config, &mut results).await;
    }

    // 5. Privileges (low-port binding)
    check_privileges(&config, &mut results);

    print_results(&results);
    exit_code(&results)
}

async fn check_config(path: &str, results: &mut Vec<CheckResult>) -> Option<AppConfig> {
    let p = Path::new(path);

    if !tokio::fs::try_exists(p).await.unwrap_or(false) {
        results.push(
            CheckResult::warn(
                "config",
                format!("config file `{path}`"),
                "file not found, sozune will start with default configuration",
            )
            .with_fix(format!(
                "create `{path}` (see https://sozune.kemeter.io/documentation/configuration/overview)"
            )),
        );
        return Some(AppConfig::default());
    }

    let content = match tokio::fs::read_to_string(p).await {
        Ok(c) => c,
        Err(e) => {
            results.push(
                CheckResult::fail(
                    "config",
                    format!("config file `{path}`"),
                    format!("cannot read: {e}"),
                )
                .with_fix("check the file permissions and ownership"),
            );
            return None;
        }
    };

    match crate::config_load::parse_yaml(p, &content) {
        Ok(cfg) => {
            results.push(CheckResult::ok("config", format!("config file `{path}`")));
            Some(cfg)
        }
        Err(e) => {
            results.push(
                CheckResult::fail("config", format!("config file `{path}`"), e.to_string())
                    .with_fix("fix the config at the reported line"),
            );
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Udp,
}

/// A socket sozune binds at startup, with the address it actually uses.
struct Listener {
    category: &'static str,
    title: String,
    host: String,
    port: u16,
    transport: Transport,
}

impl Listener {
    fn new(
        category: &'static str,
        title: impl Into<String>,
        host: &str,
        port: u16,
        transport: Transport,
    ) -> Self {
        Self {
            category,
            title: title.into(),
            host: host.to_string(),
            port,
            transport,
        }
    }

    fn port_label(&self) -> String {
        match self.transport {
            Transport::Tcp => format!("port {}", self.port),
            Transport::Udp => format!("udp port {}", self.port),
        }
    }
}

const ANY: &str = "0.0.0.0";
const LOOPBACK: &str = "127.0.0.1";

/// Every listener sozune would bind with this config. Proxy listeners take
/// all interfaces; the middleware and ACME responders stay on loopback.
fn collect_listeners(cfg: &AppConfig, results: &mut Vec<CheckResult>) -> Vec<Listener> {
    let mut listeners = vec![
        Listener::new(
            "proxy",
            "HTTP listener",
            ANY,
            cfg.proxy.http.listen_address,
            Transport::Tcp,
        ),
        Listener::new(
            "proxy",
            "HTTPS listener",
            ANY,
            cfg.proxy.https.listen_address,
            Transport::Tcp,
        ),
    ];
    for tcp in &cfg.proxy.tcp {
        listeners.push(Listener::new(
            "proxy",
            format!("TCP listener `{}`", tcp.name),
            ANY,
            tcp.listen,
            Transport::Tcp,
        ));
    }
    for udp in &cfg.proxy.udp {
        listeners.push(Listener::new(
            "proxy",
            format!("UDP listener `{}`", udp.name),
            ANY,
            udp.listen,
            Transport::Udp,
        ));
    }
    listeners.push(Listener::new(
        "middleware",
        "middleware port",
        LOOPBACK,
        cfg.middleware.port,
        Transport::Tcp,
    ));
    if let Some(acme) = cfg.acme.as_ref().filter(|a| a.enabled) {
        listeners.push(Listener::new(
            "acme",
            "ACME HTTP-01 challenge port",
            LOOPBACK,
            acme.challenge_port,
            Transport::Tcp,
        ));
        listeners.push(Listener::new(
            "acme",
            "ACME TLS-ALPN-01 responder port",
            LOOPBACK,
            acme.tls_alpn_port,
            Transport::Tcp,
        ));
    }
    if cfg.api.enabled {
        push_address_listener(
            &mut listeners,
            results,
            "api",
            "API listener",
            &cfg.api.listen_address,
        );
    }
    if cfg.dashboard.enabled {
        push_address_listener(
            &mut listeners,
            results,
            "dashboard",
            "dashboard listener",
            &cfg.dashboard.listen_address,
        );
    }
    if cfg.metrics.enabled {
        push_address_listener(
            &mut listeners,
            results,
            "metrics",
            "metrics listener",
            &cfg.metrics.listen_address,
        );
    }
    listeners
}

fn push_address_listener(
    listeners: &mut Vec<Listener>,
    results: &mut Vec<CheckResult>,
    category: &'static str,
    title: &str,
    address: &str,
) {
    match parse_listen_address(address) {
        Some((host, port)) => {
            listeners.push(Listener::new(category, title, &host, port, Transport::Tcp));
        }
        None => results.push(CheckResult::warn(
            category,
            title,
            format!("could not parse `{address}`"),
        )),
    }
}

/// Two listeners sharing a port each probe fine on their own, then the
/// second one fails at startup. Port 0 asks the kernel for a free port, so
/// it never collides.
fn check_port_conflicts(listeners: &[Listener], results: &mut Vec<CheckResult>) {
    for (i, a) in listeners.iter().enumerate() {
        for b in &listeners[i + 1..] {
            if a.port != 0
                && a.port == b.port
                && a.transport == b.transport
                && hosts_overlap(&a.host, &b.host)
            {
                results.push(
                    CheckResult::fail(
                        "ports",
                        a.port_label(),
                        format!("claimed by both {} and {}", a.title, b.title),
                    )
                    .with_fix("give each listener its own port in the config"),
                );
            }
        }
    }
}

/// A wildcard address (`0.0.0.0`, `::`) takes the port on every interface,
/// so it collides with any other host on the same port.
fn hosts_overlap(a: &str, b: &str) -> bool {
    a == b || is_unspecified(a) || is_unspecified(b)
}

fn is_unspecified(host: &str) -> bool {
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_unspecified())
        .unwrap_or(false)
}

/// `host:port`, with IPv6 hosts bracketed so the pair parses back.
fn socket_address(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Whether a sozune instance already answers on the configured API address.
/// Without the API there is no way to tell sozune from another process on
/// the same ports.
async fn sozune_is_running(cfg: &AppConfig) -> bool {
    if !cfg.api.enabled {
        return false;
    }
    let Some((host, port)) = parse_listen_address(&cfg.api.listen_address) else {
        return false;
    };
    let host = match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_unspecified() && ip.is_ipv4() => LOOPBACK.to_string(),
        Ok(ip) if ip.is_unspecified() => "::1".to_string(),
        _ => host,
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(1))
        .build()
    else {
        return false;
    };
    let url = format!("http://{}/health", socket_address(&host, port));
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

async fn check_bind(listener: &Listener, results: &mut Vec<CheckResult>) {
    let addr = socket_address(&listener.host, listener.port);
    let bound = match listener.transport {
        Transport::Tcp => tokio::net::TcpListener::bind(&addr).await.map(drop),
        Transport::Udp => tokio::net::UdpSocket::bind(&addr).await.map(drop),
    };
    let title = format!("{} ({})", listener.title, listener.port_label());
    match bound {
        Ok(()) => {
            results.push(CheckResult::ok(
                listener.category,
                format!("{title} bindable"),
            ));
        }
        Err(e) => {
            let detail = format!("cannot bind {addr}: {e}");
            let fix = if e.kind() == std::io::ErrorKind::PermissionDenied && listener.port < 1024 {
                "run sozune as root, or grant CAP_NET_BIND_SERVICE: `sudo setcap 'cap_net_bind_service=+ep' $(which sozune)`".to_string()
            } else if e.kind() == std::io::ErrorKind::AddrInUse {
                let ss = match listener.transport {
                    Transport::Tcp => "ss -lntp",
                    Transport::Udp => "ss -lnup",
                };
                format!(
                    "another process is already using this port; identify it with `{ss} | grep :{}` and stop it, or change the port in the config. If it is sozune itself, enable the API so doctor can detect a running instance",
                    listener.port
                )
            } else {
                "check the listen address and the host's network configuration".to_string()
            };
            results.push(CheckResult::fail(listener.category, title, detail).with_fix(fix));
        }
    }
}

fn parse_listen_address(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), port))
}

fn check_acme(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    let acme = match &cfg.acme {
        Some(a) if a.enabled => a,
        _ => return,
    };

    if acme.email.is_empty() {
        results.push(
            CheckResult::fail(
                "acme",
                "ACME contact email",
                "email is empty but ACME is enabled",
            )
            .with_fix("set `acme.email` in the config or via SOZUNE_ACME_EMAIL"),
        );
    } else {
        results.push(CheckResult::ok(
            "acme",
            format!("ACME email set ({})", acme.email),
        ));
    }

    check_certs_dir(&acme.certs_dir, results);

    if acme.staging {
        results.push(
            CheckResult::warn(
                "acme",
                "ACME staging mode",
                "issued certificates will not be trusted by browsers",
            )
            .with_fix("set `acme.staging=false` for production"),
        );
    }
}

/// sozune creates `certs_dir` (and any missing parent) when it stores the
/// first account or certificate, so a missing directory is fine as long as
/// its closest existing ancestor is writable. Doctor never creates it.
fn check_certs_dir(certs_dir: &str, results: &mut Vec<CheckResult>) {
    let dir = Path::new(certs_dir);
    if dir.exists() {
        match probe_writable(dir) {
            Ok(()) => results.push(CheckResult::ok(
                "acme",
                format!("ACME directory `{certs_dir}` writable"),
            )),
            Err(e) => results.push(
                CheckResult::fail(
                    "acme",
                    format!("ACME directory `{certs_dir}`"),
                    format!("not writable: {e}"),
                )
                .with_fix(format!(
                    "grant write permission to sozune: `chown $(id -un) {certs_dir}`"
                )),
            ),
        }
        return;
    }

    let ancestor = dir
        .ancestors()
        .skip(1)
        .map(|p| {
            if p.as_os_str().is_empty() {
                Path::new(".")
            } else {
                p
            }
        })
        .find(|p| p.exists())
        .unwrap_or(Path::new("."));
    match probe_writable(ancestor) {
        Ok(()) => results.push(CheckResult::ok(
            "acme",
            format!(
                "ACME directory `{certs_dir}` will be created on first use (`{}` writable)",
                ancestor.display()
            ),
        )),
        Err(e) => results.push(
            CheckResult::fail(
                "acme",
                format!("ACME directory `{certs_dir}`"),
                format!(
                    "does not exist and cannot be created: `{}` not writable: {e}",
                    ancestor.display()
                ),
            )
            .with_fix(format!(
                "create the directory and ensure sozune can write to it: `mkdir -p {certs_dir} && chown $(id -un) {certs_dir}`"
            )),
        ),
    }
}

fn probe_writable(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(".sozune-doctor-write-probe");
    std::fs::write(&probe, b"ok")?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

async fn check_providers(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    if let Some(d) = &cfg.providers.docker
        && d.enabled
    {
        check_unix_socket_or_url(results, "docker", "Docker endpoint", &d.endpoint).await;
    }
    if let Some(p) = &cfg.providers.podman
        && p.enabled
    {
        check_unix_socket_or_url(results, "podman", "Podman endpoint", &p.endpoint).await;
    }
    if let Some(s) = &cfg.providers.swarm
        && s.enabled
    {
        check_unix_socket_or_url(results, "swarm", "Swarm endpoint", &s.endpoint).await;
    }
    if let Some(n) = &cfg.providers.nomad
        && n.enabled
    {
        check_http_endpoint(results, "nomad", "Nomad endpoint", &n.endpoint).await;
    }
    if let Some(h) = &cfg.providers.http
        && h.enabled
    {
        check_http_endpoint(results, "http", "HTTP provider endpoint", &h.url).await;
    }
    if let Some(c) = &cfg.providers.consul
        && c.enabled
    {
        check_http_endpoint(results, "consul", "Consul endpoint", &c.endpoint).await;
    }
    if let Some(r) = &cfg.providers.ring
        && r.enabled
    {
        check_http_endpoint(results, "ring", "Ring endpoint", &r.endpoint).await;
    }
    if let Some(k) = &cfg.providers.kubernetes
        && k.enabled
    {
        check_kubernetes(&k.kubeconfig, results).await;
    }
    if let Some(c) = &cfg.providers.config_file
        && c.enabled
    {
        let exists = tokio::fs::try_exists(&c.path).await.unwrap_or(false);
        if exists {
            results.push(CheckResult::ok(
                "config_file",
                format!("config_file provider path `{}`", c.path),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "config_file",
                    format!("config_file provider path `{}`", c.path),
                    "file does not exist",
                )
                .with_fix("create the file or set providers.config_file.enabled=false"),
            );
        }
    }
}

/// An empty `kubeconfig` means in-cluster: the ServiceAccount token and the
/// API server address the kubelet injects into every pod.
async fn check_kubernetes(kubeconfig: &str, results: &mut Vec<CheckResult>) {
    if !kubeconfig.is_empty() {
        match tokio::fs::read(kubeconfig).await {
            Ok(_) => results.push(CheckResult::ok(
                "kubernetes",
                format!("kubeconfig `{kubeconfig}` readable"),
            )),
            Err(e) => results.push(
                CheckResult::fail(
                    "kubernetes",
                    format!("kubeconfig `{kubeconfig}`"),
                    format!("cannot read: {e}"),
                )
                .with_fix("point providers.kubernetes.kubeconfig at a readable kubeconfig, or leave it empty when running in the cluster"),
            ),
        }
        return;
    }

    let token = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    let has_host = std::env::var("KUBERNETES_SERVICE_HOST").is_ok_and(|h| !h.is_empty());
    let has_token = tokio::fs::try_exists(token).await.unwrap_or(false);
    if has_host && has_token {
        results.push(CheckResult::ok(
            "kubernetes",
            "in-cluster credentials found",
        ));
    } else {
        results.push(
            CheckResult::fail(
                "kubernetes",
                "in-cluster credentials",
                "no kubeconfig set and not running in a pod (KUBERNETES_SERVICE_HOST or the ServiceAccount token is missing)",
            )
            .with_fix("run sozune inside the cluster with a ServiceAccount, or set providers.kubernetes.kubeconfig"),
        );
    }
}

async fn check_unix_socket_or_url(
    results: &mut Vec<CheckResult>,
    category: &'static str,
    title: &str,
    endpoint: &str,
) {
    if let Some(path) = endpoint
        .strip_prefix("unix://")
        .or_else(|| endpoint.strip_prefix("/").map(|_| endpoint))
    {
        let p = Path::new(path);
        if !p.exists() {
            results.push(
                CheckResult::fail(
                    category,
                    format!("{title} `{endpoint}`"),
                    "socket does not exist",
                )
                .with_fix(format!(
                    "make sure the {category} daemon is running and exposes the socket at this path"
                )),
            );
            return;
        }
        match tokio::net::UnixStream::connect(p).await {
            Ok(_) => results.push(CheckResult::ok(category, format!("{title} reachable"))),
            Err(e) => results.push(
                CheckResult::fail(
                    category,
                    format!("{title} `{endpoint}`"),
                    format!("cannot connect: {e}"),
                )
                .with_fix(
                    "check the socket permissions (you may need to be in the `docker` group)",
                ),
            ),
        }
    } else {
        check_http_endpoint(results, category, title, endpoint).await;
    }
}

async fn check_http_endpoint(
    results: &mut Vec<CheckResult>,
    category: &'static str,
    title: &str,
    url: &str,
) {
    let Some((host, port)) = endpoint_address(url) else {
        results.push(
            CheckResult::warn(
                category,
                format!("{title} `{url}`"),
                "could not parse host:port",
            )
            .with_fix("use the form `http://host:port`"),
        );
        return;
    };
    let addr = socket_address(&host, port);
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => results.push(CheckResult::ok(
            category,
            format!("{title} reachable at {addr}"),
        )),
        Ok(Err(e)) => results.push(
            CheckResult::fail(
                category,
                format!("{title} `{url}`"),
                format!("cannot connect to {addr}: {e}"),
            )
            .with_fix(format!(
                "check that the {category} service is running and listening on {addr}"
            )),
        ),
        Err(_) => results.push(
            CheckResult::fail(
                category,
                format!("{title} `{url}`"),
                format!("connection to {addr} timed out after 2s"),
            )
            .with_fix("check network connectivity and firewall rules"),
        ),
    }
}

/// Host and port an endpoint URL connects to, with the scheme's default port
/// when none is given. IPv6 hosts come back unbracketed. A bare `host:port`
/// is read as `http://`.
fn endpoint_address(endpoint: &str) -> Option<(String, u16)> {
    let parsed = if endpoint.contains("://") {
        url::Url::parse(endpoint).ok()?
    } else {
        url::Url::parse(&format!("http://{endpoint}")).ok()?
    };
    let host = match parsed.host()? {
        url::Host::Domain(d) => d.to_string(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, parsed.port_or_known_default()?))
}

/// Only root is reported here: without it, a privileged port that cannot be
/// bound already fails its bind check with the setcap fix attached.
fn check_privileges(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    let needs_low_port = cfg.proxy.http.listen_address < 1024
        || cfg.proxy.https.listen_address < 1024
        || cfg.proxy.tcp.iter().any(|t| t.listen < 1024)
        || cfg.proxy.udp.iter().any(|u| u.listen < 1024);

    if needs_low_port && unsafe { libc_geteuid() == 0 } {
        results.push(CheckResult::ok(
            "privileges",
            "running as root, can bind privileged ports",
        ));
    }
}

// Tiny libc shim so we don't pull in the `libc` crate just for geteuid.
#[allow(non_snake_case)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

fn print_results(results: &[CheckResult]) {
    let mut by_cat: std::collections::BTreeMap<&'static str, Vec<&CheckResult>> =
        std::collections::BTreeMap::new();
    for r in results {
        by_cat.entry(r.category).or_default().push(r);
    }

    let mut out = String::new();
    for (cat, items) in &by_cat {
        writeln!(&mut out, "{cat}").unwrap();
        let last = items.len().saturating_sub(1);
        for (i, r) in items.iter().enumerate() {
            let branch = if i == last { "└─" } else { "├─" };
            let cont = if i == last { "  " } else { "│ " };
            let glyph = match r.status {
                Status::Ok => "✓",
                Status::Warn => "⚠",
                Status::Fail => "✗",
            };
            writeln!(&mut out, "{branch} {glyph} {}", r.title).unwrap();
            if let Some(d) = &r.detail {
                for line in d.lines() {
                    writeln!(&mut out, "{cont}    {line}").unwrap();
                }
            }
            if let Some(f) = &r.fix {
                writeln!(&mut out, "{cont}    → {f}").unwrap();
            }
        }
        writeln!(&mut out).unwrap();
    }

    let (ok, warn, fail) = counts(results);
    writeln!(&mut out, "{ok} ok · {warn} warning · {fail} failure").unwrap();

    print!("{out}");
}

fn counts(results: &[CheckResult]) -> (usize, usize, usize) {
    let mut ok = 0;
    let mut warn = 0;
    let mut fail = 0;
    for r in results {
        match r.status {
            Status::Ok => ok += 1,
            Status::Warn => warn += 1,
            Status::Fail => fail += 1,
        }
    }
    (ok, warn, fail)
}

fn exit_code(results: &[CheckResult]) -> i32 {
    let (_, _, fail) = counts(results);
    if fail > 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_address_ipv4() {
        assert_eq!(
            parse_listen_address("127.0.0.1:3037"),
            Some(("127.0.0.1".into(), 3037))
        );
    }

    #[test]
    fn parse_listen_address_ipv6() {
        assert_eq!(
            parse_listen_address("[::1]:3037"),
            Some(("::1".into(), 3037))
        );
    }

    #[test]
    fn parse_listen_address_bad() {
        assert_eq!(parse_listen_address("notaport"), None);
    }

    #[test]
    fn endpoint_address_defaults_the_port_and_unbrackets_ipv6() {
        let cases = [
            ("http://nomad:4646/v1", Some(("nomad", 4646))),
            ("https://consul.local", Some(("consul.local", 443))),
            ("http://[::1]", Some(("::1", 80))),
            ("http://[::1]:8500", Some(("::1", 8500))),
            ("127.0.0.1:8080", Some(("127.0.0.1", 8080))),
            ("http://", None),
        ];
        for (endpoint, expected) in cases {
            let expected = expected.map(|(h, p)| (h.to_string(), p));
            assert_eq!(endpoint_address(endpoint), expected, "{endpoint}");
        }
    }

    #[test]
    fn exit_code_is_one_with_failure() {
        let results = vec![CheckResult::fail("x", "t", "d")];
        assert_eq!(exit_code(&results), 1);
    }

    #[test]
    fn exit_code_is_zero_without_failure() {
        let results = vec![CheckResult::ok("x", "t"), CheckResult::warn("x", "t", "d")];
        assert_eq!(exit_code(&results), 0);
    }

    fn listener(title: &str, host: &str, port: u16, transport: Transport) -> Listener {
        Listener::new("test", title, host, port, transport)
    }

    #[tokio::test]
    async fn bind_check_ok_on_ephemeral_ports() {
        let mut results = Vec::new();
        check_bind(&listener("tcp", LOOPBACK, 0, Transport::Tcp), &mut results).await;
        check_bind(&listener("udp", LOOPBACK, 0, Transport::Udp), &mut results).await;
        assert!(results.iter().all(|r| r.status == Status::Ok));
    }

    #[tokio::test]
    async fn bind_check_fails_on_a_taken_port() {
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = taken.local_addr().unwrap().port();
        let mut results = Vec::new();
        check_bind(
            &listener("tcp", LOOPBACK, port, Transport::Tcp),
            &mut results,
        )
        .await;
        assert_eq!(results[0].status, Status::Fail);
        assert!(results[0].fix.as_deref().unwrap().contains("ss -lntp"));
    }

    #[tokio::test]
    async fn bind_check_brackets_ipv6_hosts() {
        let mut results = Vec::new();
        check_bind(&listener("tcp", "::1", 0, Transport::Tcp), &mut results).await;
        let detail = results[0].detail.as_deref().unwrap_or("");
        assert!(!detail.contains("invalid socket address"), "{detail}");
    }

    #[test]
    fn same_port_on_a_wildcard_and_loopback_conflicts() {
        let mut results = Vec::new();
        check_port_conflicts(
            &[
                listener("HTTP listener", ANY, 3037, Transport::Tcp),
                listener("middleware port", LOOPBACK, 3037, Transport::Tcp),
            ],
            &mut results,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, Status::Fail);
    }

    #[test]
    fn same_port_on_distinct_hosts_or_transports_does_not_conflict() {
        let mut results = Vec::new();
        check_port_conflicts(
            &[
                listener("a", "127.0.0.1", 53, Transport::Tcp),
                listener("b", "10.0.0.1", 53, Transport::Tcp),
                listener("c", ANY, 5353, Transport::Tcp),
                listener("d", ANY, 5353, Transport::Udp),
                listener("e", ANY, 0, Transport::Tcp),
                listener("f", ANY, 0, Transport::Tcp),
            ],
            &mut results,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn listeners_include_udp_acme_and_metrics() {
        let mut cfg = AppConfig::default();
        cfg.proxy.udp.push(crate::config::UdpListenerConfig {
            name: "dns".into(),
            listen: 53,
        });
        cfg.acme = Some(crate::config::AcmeConfig {
            enabled: true,
            email: "ops@example.com".into(),
            certs_dir: "/tmp".into(),
            staging: false,
            challenge_port: 3036,
            tls_alpn_port: 3040,
            resolvers: Default::default(),
        });
        cfg.metrics.enabled = true;
        let listeners = collect_listeners(&cfg, &mut Vec::new());
        let titles: Vec<&str> = listeners.iter().map(|l| l.title.as_str()).collect();
        assert!(titles.contains(&"UDP listener `dns`"));
        assert!(titles.contains(&"ACME HTTP-01 challenge port"));
        assert!(titles.contains(&"ACME TLS-ALPN-01 responder port"));
        assert!(titles.contains(&"metrics listener"));
    }

    #[tokio::test]
    async fn running_instance_is_detected_through_the_api() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let app = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        tokio::spawn(async move { axum::serve(server, app).await });

        let mut cfg = AppConfig::default();
        cfg.api.enabled = true;
        cfg.api.listen_address = addr.to_string();
        assert!(sozune_is_running(&cfg).await);

        cfg.api.enabled = false;
        assert!(!sozune_is_running(&cfg).await);
    }

    #[test]
    fn missing_certs_dir_under_a_writable_parent_is_ok_and_not_created() {
        let parent = std::env::temp_dir().join(format!("sozune-doctor-{}", std::process::id()));
        std::fs::create_dir_all(&parent).unwrap();
        let dir = parent.join("certs");
        let mut results = Vec::new();
        check_certs_dir(dir.to_str().unwrap(), &mut results);
        assert_eq!(results[0].status, Status::Ok);
        assert!(!dir.exists(), "doctor must not create certs_dir");
        std::fs::remove_dir_all(&parent).unwrap();
    }
}
