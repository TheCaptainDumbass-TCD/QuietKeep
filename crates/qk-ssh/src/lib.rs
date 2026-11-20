//! Agentless SSH transport. Host keys are pinned by SHA-256 fingerprint; an unknown key
//! aborts the connection and is returned to the caller so the user can decide whether to trust it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
pub use russh::keys::PrivateKey;
use russh::ChannelMsg;
use thiserror::Error;

const MAX_OUTPUT: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("host key {fingerprint} ({algorithm}) is not trusted yet")]
    UnknownHostKey { fingerprint: String, algorithm: String },
    #[error("host key changed: expected {expected}, got {actual}")]
    HostKeyMismatch { expected: String, actual: String },
    #[error("server presented an SSH certificate, which is not supported")]
    CertificateUnsupported,
    #[error("authentication failed for user '{0}'")]
    AuthFailed(String),
    #[error("SSH agent: {0}")]
    Agent(String),
    #[error("connection timed out")]
    Timeout,
    #[error("command output exceeded {MAX_OUTPUT} bytes")]
    OutputTooLarge,
    #[error(transparent)]
    Ssh(#[from] russh::Error),
    #[error(transparent)]
    Key(#[from] russh::keys::Error),
    #[error("key generation failed: {0}")]
    KeyGen(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SshError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Connect only if the server key matches this `SHA256:...` fingerprint.
    Pinned(String),
    /// Abort after key exchange and report the server key for user approval.
    Discover,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub address: String,
    pub port: u16,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Observed {
    Key { fingerprint: String, algorithm: String },
    Certificate,
}

struct Checker {
    policy: TrustPolicy,
    observed: Arc<Mutex<Option<Observed>>>,
}

impl client::Handler for Checker {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let observed = match server_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => Observed::Key {
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                algorithm: key.algorithm().to_string(),
            },
            russh::keys::PublicKeyOrCertificate::Certificate(_) => Observed::Certificate,
        };
        let trusted = match (&self.policy, &observed) {
            (TrustPolicy::Pinned(expected), Observed::Key { fingerprint, .. }) => expected == fingerprint,
            _ => false,
        };
        *self.observed.lock().unwrap_or_else(|p| p.into_inner()) = Some(observed);
        Ok(trusted)
    }
}

pub struct Connection {
    handle: Handle<Checker>,
    /// Fingerprint of the server key this connection was verified against.
    pub host_key: String,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub exit_status: Option<u32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.exit_status == Some(0)
    }
}

enum Auth {
    Key(Arc<PrivateKey>),
    Password(String),
    Agent,
}

pub async fn connect(
    target: &Target,
    identity: Arc<PrivateKey>,
    policy: TrustPolicy,
    timeout: Duration,
) -> Result<Connection> {
    connect_inner(target, Auth::Key(identity), policy, timeout).await
}

/// One-time password login used only to install QuietKeep's key. The host key must already be
/// pinned, so a password is never sent to an unverified machine. The password is not stored.
pub async fn connect_with_password(
    target: &Target,
    password: String,
    pinned_fingerprint: String,
    timeout: Duration,
) -> Result<Connection> {
    connect_inner(target, Auth::Password(password), TrustPolicy::Pinned(pinned_fingerprint), timeout).await
}

/// One-time login with the user's own keys through their running ssh-agent (SSH_AUTH_SOCK),
/// used only to install QuietKeep's key. The host key must already be pinned.
pub async fn connect_with_agent(target: &Target, pinned_fingerprint: String, timeout: Duration) -> Result<Connection> {
    connect_inner(target, Auth::Agent, TrustPolicy::Pinned(pinned_fingerprint), timeout).await
}

async fn connect_inner(target: &Target, auth: Auth, policy: TrustPolicy, timeout: Duration) -> Result<Connection> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    });
    let observed = Arc::new(Mutex::new(None));
    let checker = Checker { policy: policy.clone(), observed: observed.clone() };
    let addr = (target.address.as_str(), target.port);

    let connected = tokio::time::timeout(timeout, client::connect(config, addr, checker)).await;
    let mut handle = match connected {
        Err(_) => return Err(SshError::Timeout),
        Ok(Ok(handle)) => handle,
        Ok(Err(err)) => {
            let seen = observed.lock().unwrap_or_else(|p| p.into_inner()).clone();
            return Err(match (seen, policy) {
                (Some(Observed::Certificate), _) => SshError::CertificateUnsupported,
                (Some(Observed::Key { fingerprint, algorithm }), TrustPolicy::Discover) => {
                    SshError::UnknownHostKey { fingerprint, algorithm }
                }
                (Some(Observed::Key { fingerprint, .. }), TrustPolicy::Pinned(expected)) if fingerprint != expected => {
                    SshError::HostKeyMismatch { expected, actual: fingerprint }
                }
                _ => SshError::Ssh(err),
            });
        }
    };
    let host_key = match observed.lock().unwrap_or_else(|p| p.into_inner()).clone() {
        Some(Observed::Key { fingerprint, .. }) => fingerprint,
        _ => return Err(SshError::CertificateUnsupported),
    };

    let auth = match auth {
        Auth::Key(identity) => {
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            tokio::time::timeout(
                timeout,
                handle.authenticate_publickey(&target.username, PrivateKeyWithHashAlg::new(identity, hash)),
            )
            .await
            .map_err(|_| SshError::Timeout)??
        }
        Auth::Password(password) => tokio::time::timeout(timeout, handle.authenticate_password(&target.username, password))
            .await
            .map_err(|_| SshError::Timeout)??,
        Auth::Agent => {
            let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|e| SshError::Agent(format!("no running ssh-agent found ({e})")))?;
            let identities = agent.request_identities().await.map_err(|e| SshError::Agent(e.to_string()))?;
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            let mut last = None;
            for identity in identities {
                let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = identity else { continue };
                let r = tokio::time::timeout(
                    timeout,
                    handle.authenticate_publickey_with(&target.username, key, hash, &mut agent),
                )
                .await
                .map_err(|_| SshError::Timeout)?
                .map_err(|e| SshError::Agent(e.to_string()))?;
                let ok = r.success();
                last = Some(r);
                if ok {
                    break;
                }
            }
            last.ok_or_else(|| SshError::Agent("the ssh-agent has no keys loaded".into()))?
        }
    };
    if !auth.success() {
        return Err(SshError::AuthFailed(target.username.clone()));
    }
    Ok(Connection { handle, host_key })
}

impl Connection {
    pub async fn run(&self, command: &Command) -> Result<Output> {
        self.run_with_stdin(command, None).await
    }

    /// Runs a command and writes `stdin` to it, for example a sudo password for `sudo -S`.
    pub async fn run_with_stdin(&self, command: &Command, stdin: Option<&[u8]>) -> Result<Output> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command.as_str()).await?;
        if let Some(input) = stdin {
            channel.data(input).await?;
            channel.eof().await?;
        }
        let mut out = Output { exit_status: None, stdout: Vec::new(), stderr: Vec::new() };
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => out.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => out.exit_status = Some(exit_status),
                _ => {}
            }
            if out.stdout.len() + out.stderr.len() > MAX_OUTPUT {
                return Err(SshError::OutputTooLarge);
            }
        }
        Ok(out)
    }

    pub async fn close(self) -> Result<()> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
}

/// A remote command assembled from a program and arguments. Every argument is
/// single-quoted, so values such as paths or package names cannot inject shell syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command(String);

impl Command {
    pub fn new(program: &str) -> Self {
        Command(quote(program))
    }

    pub fn arg(mut self, arg: impl AsRef<str>) -> Self {
        self.0.push(' ');
        self.0.push_str(&quote(arg.as_ref()));
        self
    }

    pub fn args<I, S>(self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        args.into_iter().fold(self, |c, a| c.arg(a))
    }

    /// Runs the command non-interactively through `sudo -n`.
    pub fn sudo(program: &str) -> Self {
        Command::new("sudo").arg("-n").arg("--").arg(program)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:,+@%".contains(&b));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r#"'\''"#))
    }
}

pub fn generate_identity() -> Result<PrivateKey> {
    PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .map_err(|e| SshError::KeyGen(e.to_string()))
}

pub struct LoadedIdentity {
    pub key: PrivateKey,
    /// True when the key file on disk is encrypted with the keyring passphrase.
    pub encrypted: bool,
}

/// Loads QuietKeep's own SSH identity, creating it with mode 0600 on first use. With a
/// passphrase the file is stored encrypted, and an existing plaintext key is encrypted in place.
pub fn load_or_create_identity(path: &std::path::Path, passphrase: Option<&str>) -> Result<LoadedIdentity> {
    let keygen = |e: russh::keys::ssh_key::Error| SshError::KeyGen(e.to_string());
    if path.exists() {
        let stored = PrivateKey::from_openssh(std::fs::read_to_string(path)?).map_err(keygen)?;
        if stored.is_encrypted() {
            let Some(pass) = passphrase else {
                return Err(SshError::KeyGen(
                    "QuietKeep's SSH key is encrypted, but the desktop keyring is locked or unavailable".into(),
                ));
            };
            let key = stored.decrypt(pass).map_err(keygen)?;
            return Ok(LoadedIdentity { key, encrypted: true });
        }
        if let Some(pass) = passphrase {
            write_key_file(path, &stored.encrypt(&mut rand::rng(), pass).map_err(keygen)?, true)?;
            return Ok(LoadedIdentity { key: stored, encrypted: true });
        }
        return Ok(LoadedIdentity { key: stored, encrypted: false });
    }
    let key = generate_identity()?;
    match passphrase {
        Some(pass) => write_key_file(path, &key.encrypt(&mut rand::rng(), pass).map_err(keygen)?, false)?,
        None => write_key_file(path, &key, false)?,
    }
    Ok(LoadedIdentity { key, encrypted: passphrase.is_some() })
}

/// Writes an OpenSSH private key with mode 0600. Replacing goes through a temporary file and
/// rename so a crash never leaves a truncated key.
fn write_key_file(path: &std::path::Path, key: &PrivateKey, replace: bool) -> Result<()> {
    use std::io::Write;
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| SshError::KeyGen(e.to_string()))?;
    let target = if replace { path.with_extension("tmp") } else { path.to_path_buf() };
    if replace {
        let _ = std::fs::remove_file(&target);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&target)?;
    file.write_all(pem.as_bytes())?;
    file.sync_all()?;
    if replace {
        std::fs::rename(&target, path)?;
    }
    Ok(())
}

/// The identity's public key as an `authorized_keys` line.
pub fn public_key_openssh(key: &PrivateKey) -> Result<String> {
    let line = key.public_key().to_openssh().map_err(|e| SshError::KeyGen(e.to_string()))?;
    Ok(format!("{line} quietkeep"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let dir = std::env::temp_dir().join(format!("qk-ssh-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id");
        let _ = std::fs::remove_file(&path);
        let a = load_or_create_identity(&path, None).unwrap().key;
        let b = load_or_create_identity(&path, None).unwrap().key;
        assert_eq!(public_key_openssh(&a).unwrap(), public_key_openssh(&b).unwrap());
        assert!(public_key_openssh(&a).unwrap().starts_with("ssh-ed25519 "));
        // Migrating a plaintext key encrypts it in place and keeps the same identity.
        let c = load_or_create_identity(&path, Some("pass-1")).unwrap();
        assert!(c.encrypted);
        assert!(std::fs::read_to_string(&path).unwrap().contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(PrivateKey::from_openssh(std::fs::read_to_string(&path).unwrap()).unwrap().is_encrypted());
        assert_eq!(public_key_openssh(&c.key).unwrap(), public_key_openssh(&a).unwrap());
        let d = load_or_create_identity(&path, Some("pass-1")).unwrap();
        assert_eq!(public_key_openssh(&d.key).unwrap(), public_key_openssh(&a).unwrap());
        assert!(load_or_create_identity(&path, None).is_err());
        assert!(load_or_create_identity(&path, Some("wrong")).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("apt-get"), "apt-get");
        assert_eq!(quote("/opt/stacks/app"), "/opt/stacks/app");
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("x'; rm -rf / #"), r#"'x'\''; rm -rf / #'"#);
        assert_eq!(quote("$(id)"), "'$(id)'");
        let c = Command::sudo("apt-get").args(["install", "-y", "--only-upgrade", "pkg;id"]);
        assert_eq!(c.as_str(), "sudo -n -- apt-get install -y --only-upgrade 'pkg;id'");
    }
}
