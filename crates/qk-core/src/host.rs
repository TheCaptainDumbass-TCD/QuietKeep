use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    Apt,
    Kali,
    Pacman,
    Proxmox,
}

impl OsType {
    pub const ALL: [OsType; 4] = [OsType::Apt, OsType::Kali, OsType::Pacman, OsType::Proxmox];

    pub fn as_str(self) -> &'static str {
        match self {
            OsType::Apt => "apt",
            OsType::Kali => "kali",
            OsType::Pacman => "pacman",
            OsType::Proxmox => "proxmox",
        }
    }
}

impl fmt::Display for OsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OsType {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wanted = s.trim().to_ascii_lowercase();
        OsType::ALL
            .into_iter()
            .find(|os| os.as_str() == wanted)
            .ok_or_else(|| ValidationError::OsType(s.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("invalid host name '{0}'")]
    HostName(String),
    #[error("invalid address '{0}'")]
    Address(String),
    #[error("invalid SSH username '{0}'")]
    Username(String),
    #[error("invalid os_type '{0}', expected one of apt, kali, pacman, proxmox")]
    OsType(String),
}

/// Host definition as entered by the user, before any connection is attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSpec {
    pub name: String,
    pub address: String,
    pub username: String,
    pub os_type: OsType,
    pub is_patch_target: bool,
    pub has_docker: bool,
}

impl HostSpec {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_host_name(&self.name)?;
        validate_address(&self.address)?;
        validate_username(&self.username)?;
        Ok(())
    }
}

/// Display name: 1-64 chars of letters, digits, '.', '-' or '_', starting with a letter or digit.
pub fn validate_host_name(name: &str) -> Result<(), ValidationError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    ok.then_some(()).ok_or_else(|| ValidationError::HostName(name.to_string()))
}

/// An IP address or an RFC 1123 DNS name.
pub fn validate_address(addr: &str) -> Result<(), ValidationError> {
    if addr.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    let ok = !addr.is_empty()
        && addr.len() <= 253
        && addr.split('.').all(label_ok)
        && !addr.split('.').all(|l| l.chars().all(|c| c.is_ascii_digit()));
    ok.then_some(()).ok_or_else(|| ValidationError::Address(addr.to_string()))
}

/// Conservative POSIX login name: [a-z_][a-z0-9_-]{0,31}. Never allows shell metacharacters.
pub fn validate_username(user: &str) -> Result<(), ValidationError> {
    let mut chars = user.chars();
    let ok = user.len() <= 32
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
    ok.then_some(()).ok_or_else(|| ValidationError::Username(user.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        for good in ["admin", "root", "_svc", "keeper", "user-1"] {
            assert!(validate_username(good).is_ok(), "{good}");
        }
        for bad in ["", "Admin", "1user", "a;rm -rf /", "bob$(id)", "x y", &"a".repeat(33)] {
            assert!(validate_username(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn addresses() {
        for good in ["192.0.2.86", "::1", "fe80::1", "dev-quietkeep", "host.lab.example"] {
            assert!(validate_address(good).is_ok(), "{good}");
        }
        for bad in ["", "-bad", "a..b", "host;id", "999.1.1.1", "a b"] {
            assert!(validate_address(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_names() {
        assert!(validate_host_name("web-server-01").is_ok());
        assert!(validate_host_name("-x").is_err());
        assert!(validate_host_name("a/b").is_err());
    }

    #[test]
    fn os_type_parse() {
        assert_eq!("APT".parse::<OsType>().unwrap(), OsType::Apt);
        assert!("yum".parse::<OsType>().is_err());
    }
}
