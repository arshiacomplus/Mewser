use std::env;
use std::net::SocketAddr;
use std::process;
use std::str::FromStr;
use std::time::Duration;

use mewser_cli::{
    format_page_for_terminal, resolve_proxy_auth, BrowsingMode, ClientEngine, ClientError,
    NavigationResult, ENV_SOCKS5_PASSWORD,
};
use mewser_core::tunnel::{FixedTcpConfig, Socks5Config, Socks5Target, TunnelTransport};

struct CliArgs {
    mode: Option<BrowsingMode>,
    url: Option<String>,
    transport: TunnelTransport,
    proxy_addr: SocketAddr,
    tcp_endpoint: Option<SocketAddr>,
    gateway_addr: Option<SocketAddr>,
    proxy_user: Option<String>,
    timeout_secs: u64,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            mode: None,
            url: None,
            transport: TunnelTransport::Socks5,
            proxy_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            tcp_endpoint: None,
            gateway_addr: None,
            proxy_user: None,
            timeout_secs: 30,
        }
    }
}

fn print_usage() {
    eprintln!(
        "Mewser — Text-first browser for constrained networks\n\n\
         Usage:\n  \
           mewser --mode <resilient-text|standard-web> --url <URL> [OPTIONS]\n\n\
         Required:\n  \
           --mode, -m <MODE>              Explicit browsing mode ('resilient-text' or 'standard-web')\n  \
           --url, -u <URL>                Destination HTTP/HTTPS website URL\n\n\
         Options:\n  \
           --transport, -t <TRANSPORT>    Tunnel transport ('socks5' or 'fixed-tcp', default: socks5)\n  \
           --tcp-endpoint <ADDR>          Local MasterDNS TCP listener address (default: 127.0.0.1:1080)\n  \
           --proxy <ADDR>                 Local SOCKS5 proxy address (default: 127.0.0.1:1080)\n  \
           --gateway <ADDR>               Gateway destination address for SOCKS5 (default: 127.0.0.1:4040)\n  \
           --proxy-user <USER>            SOCKS5 proxy username (optional)\n  \
                                          (Password read from '{ENV_SOCKS5_PASSWORD}' env var or hidden prompt)\n  \
           --timeout <SECS>               Network operation timeout in seconds (default: 30)\n  \
           --help, -h                     Display this usage help\n"
    );
}

fn parse_cli_args() -> Result<CliArgs, ClientError> {
    let mut args = env::args().skip(1);
    let mut parsed = CliArgs::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            "--mode" | "-m" => {
                let val = args
                    .next()
                    .ok_or_else(|| ClientError::InvalidMode("Missing value for '--mode'".into()))?;
                parsed.mode = Some(BrowsingMode::from_str(&val)?);
            }
            "--url" | "-u" => {
                let val = args
                    .next()
                    .ok_or_else(|| ClientError::InvalidUrl("Missing value for '--url'".into()))?;
                parsed.url = Some(val);
            }
            "--transport" | "-t" => {
                let val = args.next().ok_or_else(|| {
                    ClientError::InvalidMode("Missing value for '--transport'".into())
                })?;
                match val.to_ascii_lowercase().as_str() {
                    "socks5" => parsed.transport = TunnelTransport::Socks5,
                    "fixed-tcp" | "tcp" => parsed.transport = TunnelTransport::FixedTcp,
                    other => {
                        return Err(ClientError::InvalidMode(format!(
                            "Unsupported transport '{other}'. Allowed options: 'socks5', 'fixed-tcp'"
                        )));
                    }
                }
            }
            "--proxy" => {
                let val = args
                    .next()
                    .ok_or_else(|| ClientError::Tunnel("Missing value for '--proxy'".into()))?;
                parsed.proxy_addr = val.parse().map_err(|e| {
                    ClientError::Tunnel(format!("Invalid socket address for '--proxy': {e}"))
                })?;
            }
            "--tcp-endpoint" => {
                let val = args.next().ok_or_else(|| {
                    ClientError::Tunnel("Missing value for '--tcp-endpoint'".into())
                })?;
                let addr = val.parse().map_err(|e| {
                    ClientError::Tunnel(format!("Invalid socket address for '--tcp-endpoint': {e}"))
                })?;
                parsed.tcp_endpoint = Some(addr);
            }
            "--gateway" => {
                let val = args
                    .next()
                    .ok_or_else(|| ClientError::Tunnel("Missing value for '--gateway'".into()))?;
                let addr = val.parse().map_err(|e| {
                    ClientError::Tunnel(format!("Invalid socket address for '--gateway': {e}"))
                })?;
                parsed.gateway_addr = Some(addr);
            }
            "--proxy-user" => {
                parsed.proxy_user = args.next();
            }
            "--timeout" => {
                let val = args
                    .next()
                    .ok_or_else(|| ClientError::Tunnel("Missing value for '--timeout'".into()))?;
                parsed.timeout_secs = val.parse().map_err(|e| {
                    ClientError::Tunnel(format!("Invalid integer for '--timeout': {e}"))
                })?;
            }
            "--proxy-pass" => {
                return Err(ClientError::InvalidMode(
                    "Direct '--proxy-pass' CLI arguments are forbidden for security reasons. \
                     Set the 'MEWSER_SOCKS5_PASSWORD' environment variable or provide it interactively via hidden terminal prompt."
                        .into(),
                ));
            }
            "--gateway-token" => {
                return Err(ClientError::InvalidMode(
                    "Direct '--gateway-token' CLI arguments are forbidden for security reasons. \
                     Set the 'MEWSER_GATEWAY_AUTH_TOKEN' environment variable."
                        .into(),
                ));
            }
            other => {
                return Err(ClientError::InvalidMode(format!(
                    "Unrecognized command-line argument '{other}'"
                )));
            }
        }
    }

    Ok(parsed)
}

fn main() {
    let args = match parse_cli_args() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("Error: {err}\n");
            print_usage();
            process::exit(1);
        }
    };

    let mode = match args.mode {
        Some(m) => m,
        None => {
            eprintln!("Error: {}\n", ClientError::MissingMode);
            print_usage();
            process::exit(1);
        }
    };

    let url = match args.url {
        Some(u) => u,
        None => {
            eprintln!("Error: {}\n", ClientError::MissingUrl);
            print_usage();
            process::exit(1);
        }
    };

    let auth_token = std::env::var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN)
        .ok()
        .filter(|t| !t.trim().is_empty());

    let mut engine = match args.transport {
        TunnelTransport::FixedTcp => {
            if args.gateway_addr.is_some() {
                eprintln!("Error: --gateway cannot be configured in fixed-tcp transport mode; destination is fixed by MasterDNS server configuration\n");
                print_usage();
                process::exit(1);
            }
            if args.proxy_user.is_some() {
                eprintln!("Error: Proxy authentication is only applicable to SOCKS5 transport\n");
                print_usage();
                process::exit(1);
            }

            let endpoint = args.tcp_endpoint.unwrap_or(args.proxy_addr);
            let config = FixedTcpConfig {
                endpoint,
                connect_timeout: Duration::from_secs(args.timeout_secs),
                read_timeout: Duration::from_secs(args.timeout_secs.saturating_mul(2)),
                write_timeout: Duration::from_secs(args.timeout_secs),
                max_response_bytes: 2 * 1024 * 1024,
            };
            ClientEngine::with_fixed_tcp(config)
        }
        TunnelTransport::Socks5 => {
            let auth = match resolve_proxy_auth(args.proxy_user) {
                Ok(a) => a,
                Err(err) => {
                    eprintln!("Error: {err}");
                    process::exit(1);
                }
            };

            let gateway_addr = args
                .gateway_addr
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 4040)));

            let socks_config = Socks5Config {
                proxy_addr: args.proxy_addr,
                auth,
                connect_timeout: Duration::from_secs(args.timeout_secs),
                read_timeout: Duration::from_secs(args.timeout_secs.saturating_mul(2)),
                write_timeout: Duration::from_secs(args.timeout_secs),
                max_response_bytes: 2 * 1024 * 1024,
            };
            ClientEngine::with_socks5(socks_config, Socks5Target::Ip(gateway_addr))
        }
    };
    engine.set_auth_token(auth_token);

    match engine.navigate(&url, mode) {
        Ok(NavigationResult::TextPage(page)) => {
            print!("{}", format_page_for_terminal(&page));
        }
        Err(err) => {
            eprintln!("Error: {err}");
            process::exit(1);
        }
    }
}
