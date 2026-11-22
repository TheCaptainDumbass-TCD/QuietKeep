//! Fixed package versions from the Debian and Ubuntu security trackers, read through the
//! public OSV database. Only catalog CVE IDs are sent, never anything about the hosts.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{IntelError, Result};

pub const OSV_API: &str = "https://api.osv.dev/v1/vulns/";
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const WORKERS: usize = 6;

/// One distribution package listed in a tracker record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvEntry {
    /// Such as `Debian:13` or `Ubuntu:22.04:LTS`.
    pub ecosystem: String,
    /// Source package name.
    pub package: String,
    /// First fixed version. `None` means no fix is released yet.
    pub fixed: Option<String>,
    /// The distribution's urgency rating, such as `unimportant`.
    #[serde(default)]
    pub urgency: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvCache {
    pub fetched_at: String,
    /// Every CVE that was looked up. An empty list means neither tracker has a record.
    pub cves: BTreeMap<String, Vec<OsvEntry>>,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    affected: Vec<RecordAffected>,
}

#[derive(Deserialize)]
struct RecordAffected {
    package: RecordPackage,
    #[serde(default)]
    ranges: Vec<RecordRange>,
    #[serde(default)]
    ecosystem_specific: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RecordPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct RecordRange {
    #[serde(default)]
    events: Vec<serde_json::Value>,
}

type CveEntries = (String, Vec<OsvEntry>);

pub fn valid_cve_id(id: &str) -> bool {
    let mut parts = id.splitn(3, '-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("CVE"), Some(y), Some(n))
            if y.len() == 4
                && y.bytes().all(|b| b.is_ascii_digit())
                && (4..=8).contains(&n.len())
                && n.bytes().all(|b| b.is_ascii_digit())
    )
}

fn tracked_ecosystem(e: &str) -> bool {
    e.starts_with("Debian:") || (e.starts_with("Ubuntu:") && !e.starts_with("Ubuntu:Pro:"))
}

fn parse_record(bytes: &[u8]) -> Result<Vec<OsvEntry>> {
    let r: Record = serde_json::from_slice(bytes)?;
    Ok(r.affected
        .into_iter()
        .filter(|a| tracked_ecosystem(&a.package.ecosystem))
        .map(|a| {
            let fixed = a
                .ranges
                .iter()
                .flat_map(|r| r.events.iter())
                .filter_map(|e| e.get("fixed").and_then(|f| f.as_str()))
                .max_by(|x, y| qk_core::debversion::compare(x, y))
                .map(str::to_string);
            let urgency = a
                .ecosystem_specific
                .as_ref()
                .and_then(|e| e.get("urgency"))
                .and_then(|u| u.as_str())
                .map(|u| u.chars().take(40).collect());
            OsvEntry { ecosystem: a.package.ecosystem, package: a.package.name, fixed, urgency }
        })
        .collect())
}

fn get(agent: &ureq::Agent, id: &str) -> Result<Vec<OsvEntry>> {
    let url = format!("{OSV_API}{id}");
    match agent.get(&url).header("User-Agent", concat!("QuietKeep/", env!("CARGO_PKG_VERSION"))).call() {
        Ok(mut resp) => {
            let bytes = resp
                .body_mut()
                .with_config()
                .limit(MAX_RECORD_BYTES)
                .read_to_vec()
                .map_err(|e| IntelError::Http(e.to_string()))?;
            parse_record(&bytes)
        }
        Err(ureq::Error::StatusCode(404)) => Ok(Vec::new()),
        Err(e) => Err(IntelError::Http(e.to_string())),
    }
}

/// Looks up the Debian and Ubuntu records for each CVE. Invalid IDs are skipped.
pub fn fetch(cves: &[String], fetched_at: &str) -> Result<OsvCache> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(30))).build().into();
    let ids: Vec<&String> = cves.iter().filter(|c| valid_cve_id(c)).collect();
    let chunk = ids.len().div_ceil(WORKERS).max(1);
    let results: Vec<Result<Vec<CveEntries>>> = std::thread::scope(|s| {
        let handles: Vec<_> = ids
            .chunks(chunk)
            .map(|part| {
                let agent = agent.clone();
                s.spawn(move || {
                    part.iter()
                        .map(|cve| {
                            let mut entries = get(&agent, &format!("DEBIAN-{cve}"))?;
                            entries.extend(get(&agent, &format!("UBUNTU-{cve}"))?);
                            Ok(((*cve).clone(), entries))
                        })
                        .collect()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(IntelError::Http("lookup thread failed".into())))).collect()
    });
    let mut cache = OsvCache { fetched_at: fetched_at.to_string(), cves: BTreeMap::new() };
    for r in results {
        cache.cves.extend(r?);
    }
    Ok(cache)
}

pub fn save_cache(path: &Path, cache: &OsvCache) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(cache)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

pub fn load_cache(path: &Path) -> Result<Option<OsvCache>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The tracker ecosystems that apply to a host's /etc/os-release `ID` and `VERSION_ID`, in
/// priority order. Kali rolling follows Debian testing. Parrot is built on Debian stable,
/// with Debian testing as a fallback for its newer kernels. `testing` comes from
/// [`debian_testing`].
pub fn ecosystems(os_id: Option<&str>, os_version: Option<&str>, testing: Option<&str>) -> Vec<String> {
    let v = os_version.unwrap_or("").trim();
    if v.is_empty() {
        return Vec::new();
    }
    let major = v.split('.').next().unwrap_or(v);
    let testing = testing.map(str::to_string);
    match os_id {
        Some("debian") => vec![format!("Debian:{major}")],
        Some("ubuntu") => vec![format!("Ubuntu:{v}:LTS"), format!("Ubuntu:{v}")],
        Some("kali") => testing.into_iter().collect(),
        Some("parrot") => {
            let stable = match major {
                "5" => Some("Debian:11"),
                "6" => Some("Debian:12"),
                "7" => Some("Debian:13"),
                _ => None,
            };
            stable.map(str::to_string).into_iter().chain(testing).collect()
        }
        _ => Vec::new(),
    }
}

/// Debian testing, the highest numbered Debian release in the tracker data.
pub fn debian_testing(osv: &OsvCache) -> Option<String> {
    osv.cves
        .values()
        .flatten()
        .filter_map(|e| e.ecosystem.strip_prefix("Debian:")?.parse::<u32>().ok())
        .max()
        .map(|n| format!("Debian:{n}"))
}

const UBUNTU_KERNELS: &[(&str, &str)] =
    &[("6.8.0", "Ubuntu:24.04:LTS"), ("6.14.0", "Ubuntu:25.04"), ("6.17.0", "Ubuntu:25.10"), ("7.0.0", "Ubuntu:26.04:LTS")];

/// The Ubuntu release whose `linux` package a Proxmox kernel is built on, such as
/// `Ubuntu:26.04:LTS` for `7.0.0-44.44`. `None` when the tracker data has no such release,
/// for example after it reached end of life.
pub fn ubuntu_release(base: &str, osv: &OsvCache) -> Option<String> {
    let upstream = base.split('-').next()?;
    let prefix = format!("{upstream}-");
    let entries = || osv.cves.values().flatten();
    let general = |eco: &str| eco.starts_with("Ubuntu:") && !eco.starts_with("Ubuntu:Pro:") && eco.matches(':').count() <= 2;
    let mut found: Vec<&str> = entries()
        .filter(|e| e.package == "linux" && general(&e.ecosystem) && e.fixed.as_deref().is_some_and(|f| f.starts_with(&prefix)))
        .map(|e| e.ecosystem.as_str())
        .collect();
    found.sort_unstable();
    found.dedup();
    if let [eco] = found.as_slice() {
        return Some(eco.to_string());
    }
    let (_, eco) = UBUNTU_KERNELS.iter().find(|(u, _)| *u == upstream)?;
    entries().any(|e| e.ecosystem == *eco).then(|| eco.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_keep_tracked_ecosystems_and_fixed_versions() {
        let json = br#"{"id":"UBUNTU-CVE-2021-3156","affected":[
            {"package":{"name":"sudo","ecosystem":"Ubuntu:Pro:14.04:LTS"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.8.9"}]}]},
            {"package":{"name":"sudo","ecosystem":"Ubuntu:20.04:LTS"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.8.31-1ubuntu1.2"}]}],"ecosystem_specific":{"urgency":"unimportant"}},
            {"package":{"name":"linux-aws-6.8","ecosystem":"Ubuntu:22.04:LTS"},"ranges":[{"events":[{"introduced":"0"}]}]}]}"#;
        let e = parse_record(json).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].fixed.as_deref(), Some("1.8.31-1ubuntu1.2"));
        assert_eq!(e[1].fixed, None);
        assert_eq!(e[0].urgency.as_deref(), Some("unimportant"));
        assert_eq!(e[1].urgency, None);
        assert_eq!(ecosystems(Some("debian"), Some("13"), None), vec!["Debian:13"]);
        assert_eq!(ecosystems(Some("ubuntu"), Some("22.04"), None)[0], "Ubuntu:22.04:LTS");
        assert!(ecosystems(Some("kali"), Some("2026.3"), None).is_empty());
        assert_eq!(ecosystems(Some("kali"), Some("2026.3"), Some("Debian:14")), vec!["Debian:14"]);
        assert_eq!(ecosystems(Some("parrot"), Some("7.4"), Some("Debian:14")), vec!["Debian:13", "Debian:14"]);
        assert!(ecosystems(Some("arch"), Some("x"), Some("Debian:14")).is_empty());
        assert!(!valid_cve_id("CVE-2024-1/../x"));
    }

    #[test]
    fn testing_and_ubuntu_kernel_releases() {
        let e = |eco: &str, fixed: Option<&str>| OsvEntry { ecosystem: eco.into(), package: "linux".into(), fixed: fixed.map(str::to_string), urgency: None };
        let mut c = OsvCache::default();
        c.cves.insert("CVE-1".into(), vec![e("Debian:13", Some("6.12.1-1")), e("Debian:14", None), e("Ubuntu:26.04:LTS", Some("7.0.0-45.45"))]);
        c.cves.insert("CVE-2".into(), vec![e("Ubuntu:24.04:LTS", Some("6.8.0-90.91")), e("Ubuntu:Nvidia-BlueField:24.04:LTS", Some("7.0.0-1.1"))]);
        assert_eq!(debian_testing(&c).as_deref(), Some("Debian:14"));
        assert_eq!(ubuntu_release("7.0.0-44.44", &c).as_deref(), Some("Ubuntu:26.04:LTS"));
        assert_eq!(ubuntu_release("6.8.0-60.63", &c).as_deref(), Some("Ubuntu:24.04:LTS"));
        assert_eq!(ubuntu_release("6.17.0-8.8", &c), None);
        assert_eq!(ubuntu_release("5.0.0-1.1", &c), None);
    }
}
