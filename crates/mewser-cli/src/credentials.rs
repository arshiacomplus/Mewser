use std::env;
use std::io::{self, IsTerminal, Write};

use mewser_core::tunnel::Socks5Auth;

use crate::error::ClientError;

pub const ENV_SOCKS5_PASSWORD: &str = "MEWSER_SOCKS5_PASSWORD";
pub const ENV_GATEWAY_AUTH_TOKEN: &str = "MEWSER_GATEWAY_AUTH_TOKEN";

pub fn resolve_proxy_auth(username: Option<String>) -> Result<Option<Socks5Auth>, ClientError> {
    let username = match username {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => return Ok(None),
    };

    if let Ok(pass) = env::var(ENV_SOCKS5_PASSWORD) {
        if !pass.is_empty() {
            return Ok(Some(Socks5Auth {
                username,
                password: pass,
            }));
        }
    }

    if io::stdin().is_terminal() {
        let password =
            prompt_hidden_password(&format!("Enter SOCKS5 password for user '{username}': "))
                .map_err(|e| {
                    ClientError::Tunnel(format!("Failed to read password from terminal: {e}"))
                })?;

        return Ok(Some(Socks5Auth { username, password }));
    }

    Err(ClientError::Tunnel(format!(
        "Authentication required for user '{username}', but '{ENV_SOCKS5_PASSWORD}' environment variable is not set and terminal input is unavailable"
    )))
}

#[cfg(unix)]
pub fn prompt_hidden_password(prompt: &str) -> io::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let stdin_fd = libc::STDIN_FILENO;
    let mut termios = std::mem::MaybeUninit::uninit();
    if unsafe { libc::tcgetattr(stdin_fd, termios.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut termios = unsafe { termios.assume_init() };
    let original = termios;

    termios.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(stdin_fd, libc::TCSANOW, &termios) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut password = String::new();
    let read_res = io::stdin().read_line(&mut password);

    unsafe { libc::tcsetattr(stdin_fd, libc::TCSANOW, &original) };
    eprintln!();

    read_res?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    Ok(password)
}

#[cfg(not(unix))]
pub fn prompt_hidden_password(prompt: &str) -> io::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    if password.ends_with('\n') {
        password.pop();
    }
    if password.ends_with('\r') {
        password.pop();
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_auth_from_env_variable() {
        let test_user = "test_user_env";
        let test_pass = "temporary_test_env_pass_123";

        env::set_var(ENV_SOCKS5_PASSWORD, test_pass);
        let resolved = resolve_proxy_auth(Some(test_user.into())).unwrap().unwrap();
        env::remove_var(ENV_SOCKS5_PASSWORD);

        assert_eq!(resolved.username, test_user);
        assert_eq!(resolved.password, test_pass);
    }

    #[test]
    fn test_resolve_auth_returns_none_when_no_user() {
        assert_eq!(resolve_proxy_auth(None).unwrap(), None);
        assert_eq!(resolve_proxy_auth(Some("".into())).unwrap(), None);
    }
}
