//! Pending package updates reported by a host's package manager.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageUpdate {
    pub name: String,
    pub current_version: Option<String>,
    pub available_version: String,
    /// Repository or pocket the update comes from, when the package manager reports it.
    pub source: Option<String>,
    pub security: bool,
    /// Set when `apt-get upgrade` will skip this update: "phasing" or "kept back".
    pub held: Option<String>,
}

/// Parses `apt list --upgradable`, e.g.
/// `openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]`.
pub fn parse_apt_upgradable(output: &str) -> Vec<PackageUpdate> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, rest) = line.split_once('/')?;
            if name.is_empty() || name.contains(' ') {
                return None;
            }
            let mut words = rest.split_whitespace();
            let source = words.next()?;
            let available = words.next()?;
            let current = rest
                .split_once("[upgradable from:")
                .map(|(_, v)| v.trim_end_matches(']').trim().to_string())
                .filter(|v| !v.is_empty());
            Some(PackageUpdate {
                name: name.to_string(),
                current_version: current,
                available_version: available.to_string(),
                source: Some(source.to_string()),
                security: source.split(',').any(|s| s.ends_with("-security")),
                held: None,
            })
        })
        .collect()
}

/// Parses `checkupdates` (`name old -> new`) or `pacman -Qu` (`name old -> new` or `name new`).
pub fn parse_pacman_updates(output: &str) -> Vec<PackageUpdate> {
    output
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                [name, old, "->", new, ..] => Some((name, Some(old), new)),
                [name, new] => Some((name, None, new)),
                _ => None,
            }
            .filter(|(name, _, _)| !name.starts_with("::") && !name.contains(':'))
            .map(|(name, old, new)| PackageUpdate {
                name: name.to_string(),
                current_version: old.map(|o| o.to_string()),
                available_version: new.to_string(),
                source: None,
                security: false,
                held: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt() {
        let out = "Listing... Done\n\
            openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]\n\
            docker-ce/noble 5:27.1.0-1~ubuntu.24.04~noble amd64 [upgradable from: 5:26.1.0-1~ubuntu.24.04~noble]\n\
            \n\
            WARNING: apt does not have a stable CLI interface.\n";
        let u = parse_apt_upgradable(out);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].name, "openssl");
        assert_eq!(u[0].available_version, "3.0.13-0ubuntu3.5");
        assert_eq!(u[0].current_version.as_deref(), Some("3.0.13-0ubuntu3.4"));
        assert!(u[0].security);
        assert_eq!(u[1].name, "docker-ce");
        assert!(!u[1].security);
        assert_eq!(u[1].current_version.as_deref(), Some("5:26.1.0-1~ubuntu.24.04~noble"));
    }

    #[test]
    fn pacman() {
        let out = "linux 6.9.1.arch1-1 -> 6.9.2.arch1-1\nfirefox 127.0-1\n:: warning\n";
        let u = parse_pacman_updates(out);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].current_version.as_deref(), Some("6.9.1.arch1-1"));
        assert_eq!(u[0].available_version, "6.9.2.arch1-1");
        assert_eq!(u[1].current_version, None);
        assert_eq!(u[1].available_version, "127.0-1");
    }
}

/// Parses `LC_ALL=C apt-get -s upgrade` and returns the packages apt will skip, with the reason.
pub fn parse_apt_held(simulation: &str) -> std::collections::HashMap<String, &'static str> {
    let mut held = std::collections::HashMap::new();
    let mut reason = None;
    for line in simulation.lines() {
        if line.starts_with("The following upgrades have been deferred due to phasing") {
            reason = Some("phasing");
        } else if line.starts_with("The following packages have been kept back") {
            reason = Some("kept back");
        } else if line.starts_with("  ") {
            if let Some(r) = reason {
                for name in line.split_whitespace() {
                    held.insert(name.to_string(), r);
                }
            }
        } else {
            reason = None;
        }
    }
    held
}

#[cfg(test)]
mod held_tests {
    use super::parse_apt_held;

    #[test]
    fn parses_phasing_and_kept_back() {
        let sim = "Reading package lists...\nThe following upgrades have been deferred due to phasing:\n  fwupd libfwupd3\n  kwin-common\nThe following packages have been kept back:\n  linux-generic\n0 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.\n";
        let h = parse_apt_held(sim);
        assert_eq!(h.len(), 4);
        assert_eq!(h["fwupd"], "phasing");
        assert_eq!(h["kwin-common"], "phasing");
        assert_eq!(h["linux-generic"], "kept back");
    }
}

/// A package installed on a host and the source package it was built from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_version: String,
}
