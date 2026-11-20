//! CISA Known Exploited Vulnerabilities catalog. The feed is downloaded only when the
//! user allows it, then cached locally so the catalog stays usable offline.

pub mod registry;

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const MAX_FEED_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum IntelError {
    #[error("download failed: {0}")]
    Http(String),
    #[error("feed is not valid: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("cache error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IntelError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub catalog_version: String,
    pub date_released: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    #[serde(default)]
    pub known_ransomware_campaign_use: String,
    #[serde(default)]
    pub notes: String,
}

const LINUX_TERMS: &[&str] = &[
    "linux", "debian", "ubuntu", "canonical", "red hat", "kali", "arch", "proxmox", "docker",
    "openssl", "openssh", "sudo", "polkit", "glibc", "gnu", "systemd", "apache", "nginx",
    "samba", "exim", "bash", "xz", "kubernetes", "jenkins", "gitlab", "grafana", "php",
];

impl Vulnerability {
    pub fn ransomware(&self) -> bool {
        self.known_ransomware_campaign_use.eq_ignore_ascii_case("known")
    }

    /// Vendors and products commonly found on Debian, Ubuntu, Kali, Arch and Proxmox hosts.
    pub fn linux_related(&self) -> bool {
        let hay = format!("{} {}", self.vendor_project, self.product).to_lowercase();
        let words: Vec<&str> = hay.split(|c: char| !c.is_alphanumeric()).collect();
        LINUX_TERMS
            .iter()
            .any(|t| if t.contains(' ') { hay.contains(t) } else { words.contains(t) })
    }
}

pub fn parse(bytes: &[u8]) -> Result<Catalog> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Downloads the feed over HTTPS. Call only after the user has allowed it.
pub fn download() -> Result<Vec<u8>> {
    let mut resp = ureq::get(KEV_URL)
        .header("User-Agent", concat!("QuietKeep/", env!("CARGO_PKG_VERSION")))
        .call()
        .map_err(|e| IntelError::Http(e.to_string()))?;
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(MAX_FEED_BYTES)
        .read_to_vec()
        .map_err(|e| IntelError::Http(e.to_string()))?;
    parse(&bytes)?;
    Ok(bytes)
}

pub fn save_cache(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

pub fn load_cache(path: &Path) -> Result<Option<Catalog>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(parse(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub catalog_version: String,
    pub date_released: String,
    pub total: usize,
    pub ransomware: usize,
    pub linux_related: usize,
    pub added_last_30_days: usize,
    pub top_vendors: Vec<(String, usize)>,
}

/// `today` is an ISO date (YYYY-MM-DD) used for the 30-day window.
pub fn summarize(catalog: &Catalog, today: &str) -> Summary {
    let cutoff = days_before(today, 30);
    let mut vendors: HashMap<&str, usize> = HashMap::new();
    for v in &catalog.vulnerabilities {
        *vendors.entry(v.vendor_project.as_str()).or_default() += 1;
    }
    let mut top: Vec<(String, usize)> = vendors.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top.truncate(8);
    let vulns = &catalog.vulnerabilities;
    Summary {
        catalog_version: catalog.catalog_version.clone(),
        date_released: catalog.date_released.clone(),
        total: vulns.len(),
        ransomware: vulns.iter().filter(|v| v.ransomware()).count(),
        linux_related: vulns.iter().filter(|v| v.linux_related()).count(),
        added_last_30_days: vulns.iter().filter(|v| v.date_added.as_str() >= cutoff.as_str()).count(),
        top_vendors: top,
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Filter {
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub linux_only: bool,
    #[serde(default)]
    pub ransomware_only: bool,
}

/// Newest first, capped at `limit`.
pub fn filter(catalog: &Catalog, f: &Filter, limit: usize) -> Vec<Vulnerability> {
    let q = f.search.trim().to_lowercase();
    let mut out: Vec<&Vulnerability> = catalog
        .vulnerabilities
        .iter()
        .filter(|v| !f.linux_only || v.linux_related())
        .filter(|v| !f.ransomware_only || v.ransomware())
        .filter(|v| {
            q.is_empty()
                || [&v.cve_id, &v.vendor_project, &v.product, &v.vulnerability_name, &v.short_description]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&q))
        })
        .collect();
    out.sort_by(|a, b| b.date_added.cmp(&a.date_added).then(b.cve_id.cmp(&a.cve_id)));
    out.into_iter().take(limit).cloned().collect()
}

pub fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Civil-date arithmetic on YYYY-MM-DD strings, so no date crate is needed.
fn days_before(date: &str, days: i64) -> String {
    let parts: Vec<i64> = date.split('-').filter_map(|p| p.parse().ok()).collect();
    let [y, m, d] = parts[..] else { return String::new() };
    let (y, m, d) = civil_from_days(days_from_civil(y, m, d) - days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = r#"{"title":"CISA","catalogVersion":"2026.11.18","dateReleased":"2026-11-18T19:17:41Z","count":3,
    "vulnerabilities":[
     {"cveID":"CVE-2024-3094","vendorProject":"XZ Utils","product":"XZ Utils","vulnerabilityName":"XZ backdoor","dateAdded":"2026-11-01","shortDescription":"Embedded malicious code.","requiredAction":"Apply updates.","dueDate":"2026-11-22","knownRansomwareCampaignUse":"Unknown","notes":"","cwes":["CWE-506"]},
     {"cveID":"CVE-2021-3156","vendorProject":"Sudo","product":"Sudo","vulnerabilityName":"Sudo heap overflow","dateAdded":"2022-04-06","shortDescription":"Baron Samedit.","requiredAction":"Apply updates.","dueDate":"2022-04-27","knownRansomwareCampaignUse":"Known","notes":"","cwes":[]},
     {"cveID":"CVE-2020-29583","vendorProject":"Zyxel","product":"Multiple Products","vulnerabilityName":"Hard-coded credentials","dateAdded":"2021-11-03","shortDescription":"zyfwp account.","requiredAction":"Apply updates.","dueDate":"2022-05-03","knownRansomwareCampaignUse":"Unknown","notes":""}
    ]}"#;

    #[test]
    fn parses_and_summarizes() {
        let c = parse(FEED.as_bytes()).unwrap();
        let s = summarize(&c, "2026-11-19");
        assert_eq!((s.total, s.ransomware, s.linux_related, s.added_last_30_days), (3, 1, 2, 1));
        assert_eq!(s.top_vendors.len(), 3);
    }

    #[test]
    fn filters_newest_first() {
        let c = parse(FEED.as_bytes()).unwrap();
        assert_eq!(filter(&c, &Filter::default(), 10)[0].cve_id, "CVE-2024-3094");
        assert_eq!(filter(&c, &Filter { linux_only: true, ..Default::default() }, 10).len(), 2);
        let r = filter(&c, &Filter { ransomware_only: true, ..Default::default() }, 10);
        assert_eq!(r[0].cve_id, "CVE-2021-3156");
        assert_eq!(filter(&c, &Filter { search: "zyfwp".into(), ..Default::default() }, 10).len(), 1);
    }

    #[test]
    fn date_math() {
        assert_eq!(days_before("2026-03-01", 1), "2026-02-28");
        assert_eq!(days_before("2024-03-01", 1), "2024-02-29");
        assert_eq!(days_before("2026-11-19", 30), "2026-10-20");
    }

    #[test]
    fn real_feed_if_present() {
        if let Ok(bytes) = std::fs::read("/tmp/kev.json") {
            let c = parse(&bytes).unwrap();
            let s = summarize(&c, &today_utc());
            assert!(s.total > 1000 && s.linux_related > 50, "{s:?}");
        }
    }
}
