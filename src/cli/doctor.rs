use std::fmt::Write;
use std::path::Path;

use clap::Args;

use crate::config::AppConfig;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Skip checks that touch the network (provider sockets, ACME directory).
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

    // 2. Ports bindable
    check_proxy_ports(&config, &mut results).await;
    check_middleware_port(&config, &mut results).await;
    check_api_port(&config, &mut results).await;
    check_dashboard_port(&config, &mut results).await;

    // 3. ACME
    check_acme(&config, &mut results);

    // 4. Providers (network checks, skipped in --offline)
    if !args.offline {
        check_providers(&config, &mut results).await;
    }

    // 5. Privileges (low-port binding without root)
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
                "create `{path}` (see https://sozune.dev/docs/configuration)"
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
                    .with_fix("run `sozune validate` for a per-candidate diagnostic, or fix the YAML at the reported line"),
            );
            None
        }
    }
}

async fn check_proxy_ports(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    check_tcp_port(
        results,
        "proxy",
        "HTTP listener",
        cfg.proxy.http.listen_address,
    )
    .await;
    check_tcp_port(
        results,
        "proxy",
        "HTTPS listener",
        cfg.proxy.https.listen_address,
    )
    .await;
    for tcp in &cfg.proxy.tcp {
        check_tcp_port(
            results,
            "proxy",
            &format!("TCP listener `{}`", tcp.name),
            tcp.listen,
        )
        .await;
    }
}

async fn check_middleware_port(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    check_tcp_port(
        results,
        "middleware",
        "middleware port",
        cfg.middleware.port,
    )
    .await;
}

async fn check_api_port(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    if !cfg.api.enabled {
        return;
    }
    match parse_listen_address(&cfg.api.listen_address) {
        Some((host, port)) => {
            check_tcp_port_with_host(results, "api", "API listener", &host, port).await
        }
        None => results.push(CheckResult::warn(
            "api",
            "API listener",
            format!("could not parse `{}`", cfg.api.listen_address),
        )),
    }
}

async fn check_dashboard_port(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    if !cfg.dashboard.enabled {
        return;
    }
    match parse_listen_address(&cfg.dashboard.listen_address) {
        Some((host, port)) => {
            check_tcp_port_with_host(results, "dashboard", "dashboard listener", &host, port).await
        }
        None => results.push(CheckResult::warn(
            "dashboard",
            "dashboard listener",
            format!("could not parse `{}`", cfg.dashboard.listen_address),
        )),
    }
}

async fn check_tcp_port(
    results: &mut Vec<CheckResult>,
    category: &'static str,
    title: &str,
    port: u16,
) {
    check_tcp_port_with_host(results, category, title, "0.0.0.0", port).await
}

async fn check_tcp_port_with_host(
    results: &mut Vec<CheckResult>,
    category: &'static str,
    title: &str,
    host: &str,
    port: u16,
) {
    let addr = format!("{host}:{port}");
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            drop(listener);
            results.push(CheckResult::ok(
                category,
                format!("{title} (port {port}) bindable"),
            ));
        }
        Err(e) => {
            let detail = format!("cannot bind {addr}: {e}");
            let fix = if e.kind() == std::io::ErrorKind::PermissionDenied && port < 1024 {
                "run sozune as root, or grant CAP_NET_BIND_SERVICE: `sudo setcap 'cap_net_bind_service=+ep' $(which sozune)`"
            } else if e.kind() == std::io::ErrorKind::AddrInUse {
                "another process is already using this port; identify it with `ss -lntp | grep :PORT` and stop it, or change the port in the config"
            } else {
                "check the listen address and the host's network configuration"
            };
            results.push(
                CheckResult::fail(category, format!("{title} (port {port})"), detail).with_fix(fix),
            );
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

    let dir = Path::new(&acme.certs_dir);
    if !dir.exists()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        results.push(
            CheckResult::fail(
                "acme",
                format!("ACME directory `{}`", acme.certs_dir),
                format!("does not exist and cannot be created: {e}"),
            )
            .with_fix(format!(
                "create the directory and ensure sozune can write to it: `mkdir -p {} && chown $(id -un) {}`",
                acme.certs_dir, acme.certs_dir
            )),
        );
        return;
    }

    let probe = dir.join(".sozune-doctor-write-probe");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            results.push(CheckResult::ok(
                "acme",
                format!("ACME directory `{}` writable", acme.certs_dir),
            ));
        }
        Err(e) => {
            results.push(
                CheckResult::fail(
                    "acme",
                    format!("ACME directory `{}`", acme.certs_dir),
                    format!("not writable: {e}"),
                )
                .with_fix(format!(
                    "grant write permission to sozune: `chown $(id -un) {}`",
                    acme.certs_dir
                )),
            );
        }
    }

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
    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        None => (
            host_port.to_string(),
            if url.starts_with("https://") { 443 } else { 80 },
        ),
    };
    if host.is_empty() {
        results.push(
            CheckResult::warn(
                category,
                format!("{title} `{url}`"),
                "could not parse host:port",
            )
            .with_fix("use the form `http://host:port`"),
        );
        return;
    }
    let addr = format!("{host}:{port}");
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

fn check_privileges(cfg: &AppConfig, results: &mut Vec<CheckResult>) {
    let needs_low_port = cfg.proxy.http.listen_address < 1024
        || cfg.proxy.https.listen_address < 1024
        || cfg.proxy.tcp.iter().any(|t| t.listen < 1024);

    if !needs_low_port {
        return;
    }

    let is_root = unsafe { libc_geteuid() == 0 };
    if is_root {
        results.push(CheckResult::ok(
            "privileges",
            "running as root, can bind privileged ports",
        ));
    } else {
        // We can't reliably probe CAP_NET_BIND_SERVICE without libc bindings,
        // so we rely on the bind probe results elsewhere and just hint here.
        results.push(
            CheckResult::warn(
                "privileges",
                "binding privileged ports as non-root",
                "ports below 1024 require root or CAP_NET_BIND_SERVICE; if the bind checks above passed, you already have it",
            )
            .with_fix("if a port check failed: `sudo setcap 'cap_net_bind_service=+ep' $(which sozune)`"),
        );
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
    fn exit_code_is_one_with_failure() {
        let results = vec![CheckResult::fail("x", "t", "d")];
        assert_eq!(exit_code(&results), 1);
    }

    #[test]
    fn exit_code_is_zero_without_failure() {
        let results = vec![CheckResult::ok("x", "t"), CheckResult::warn("x", "t", "d")];
        assert_eq!(exit_code(&results), 0);
    }

    #[tokio::test]
    async fn tcp_port_bind_check_ok_on_random_port() {
        let mut results = Vec::new();
        // Bind to port 0 → kernel assigns. Then close, then re-probe.
        // We can't easily capture the assigned port across two binds, so
        // just check that probing port 0 returns Ok.
        check_tcp_port(&mut results, "test", "ephemeral", 0).await;
        assert_eq!(results[0].status, Status::Ok);
    }
}
