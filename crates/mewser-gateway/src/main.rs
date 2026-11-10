use mewser_gateway::{Gateway, GatewayConfig, GatewayServer};
use std::net::SocketAddr;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
static RUNNING: AtomicBool = AtomicBool::new(true);

#[cfg(unix)]
extern "C" fn sig_handler(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr_str =
        std::env::var("MEWSER_GATEWAY_BIND").unwrap_or_else(|_| "127.0.0.1:4040".to_string());

    let bind_addr: SocketAddr = bind_addr_str
        .parse()
        .map_err(|e| format!("Invalid MEWSER_GATEWAY_BIND address '{bind_addr_str}': {e}"))?;

    // Invariant: Gateway must bind strictly to a loopback address unless explicitly authorized with firewall isolation
    let allow_non_loopback = match std::env::var("MEWSER_GATEWAY_ALLOW_NON_LOOPBACK") {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => false,
    };
    if !bind_addr.ip().is_loopback() && !allow_non_loopback {
        eprintln!(
            "Fatal: Gateway must bind exclusively to a loopback address. \
             Set MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=1 only when protected by local firewall isolation."
        );
        std::process::exit(1);
    }

    // Secure default: authentication is mandatory unless explicitly opted out for local testing
    let require_auth = match std::env::var("MEWSER_GATEWAY_REQUIRE_AUTH") {
        Ok(v) => v != "0" && !v.eq_ignore_ascii_case("false"),
        Err(_) => true,
    };

    let auth_token = std::env::var("MEWSER_GATEWAY_AUTH_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty());

    if require_auth && auth_token.is_none() {
        eprintln!(
            "Fatal: Authentication token is required (MEWSER_GATEWAY_AUTH_TOKEN). \
             Set MEWSER_GATEWAY_REQUIRE_AUTH=false only for unauthenticated local development."
        );
        std::process::exit(1);
    }

    let config = GatewayConfig {
        listen_addr: bind_addr,
        allow_loopback_for_testing: false,
        auth_token,
        ..Default::default()
    };

    let gateway = Gateway::new(config);
    let server = GatewayServer::bind(bind_addr, gateway)?;
    println!("Mewser Gateway listening on http://{bind_addr}");

    #[cfg(unix)]
    {
        unsafe {
            libc::signal(libc::SIGINT, sig_handler as usize);
            libc::signal(libc::SIGTERM, sig_handler as usize);
        }

        let (handle, join_handle) = server.spawn();

        while RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        eprintln!("Received termination signal, shutting down Gateway...");
        handle.stop();
        let _ = join_handle.join();
        eprintln!("Mewser Gateway shutdown complete.");
    }

    #[cfg(not(unix))]
    {
        let (_handle, join_handle) = server.spawn();
        join_handle.join().unwrap();
    }

    Ok(())
}
