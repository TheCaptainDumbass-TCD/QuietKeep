//! Matches catalog entries to the software installed on saved hosts. The catalog lists
//! products, not version ranges, so a match means the product is installed and the host's
//! security updates should be checked. It does not prove the host is vulnerable.

use serde::Serialize;

use crate::osv::{ecosystems, OsvCache};
use crate::Catalog;
use qk_core::debversion;
use std::cmp::Ordering;

struct Rule {
    vendors: &'static [&'static str],
    products: &'static [&'static str],
    packages: &'static [&'static str],
    prefixes: &'static [&'static str],
    images: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule { vendors: &["linux"], products: &["kernel"], packages: &["linux", "linux-lts", "linux-zen"], prefixes: &["linux-image-", "proxmox-kernel-", "pve-kernel-"], images: &[] },
    Rule { vendors: &["openbsd", "openssh"], products: &["openssh"], packages: &["openssh-server", "openssh"], prefixes: &[], images: &[] },
    Rule { vendors: &["sudo", "todd miller"], products: &["sudo"], packages: &["sudo"], prefixes: &[], images: &[] },
    Rule { vendors: &["gnu"], products: &["glibc", "c library"], packages: &["libc6", "glibc"], prefixes: &[], images: &[] },
    Rule { vendors: &["gnu"], products: &["bash"], packages: &["bash"], prefixes: &[], images: &[] },
    Rule { vendors: &["apache"], products: &["http server"], packages: &["apache2", "httpd", "apache"], prefixes: &[], images: &["httpd"] },
    Rule { vendors: &["nginx", "f5"], products: &["nginx"], packages: &["nginx", "nginx-core", "nginx-full", "nginx-light"], prefixes: &[], images: &["nginx"] },
    Rule { vendors: &["php"], products: &["php"], packages: &["php"], prefixes: &["php8", "php7", "libapache2-mod-php"], images: &["php"] },
    Rule { vendors: &["samba"], products: &["samba"], packages: &["samba"], prefixes: &[], images: &[] },
    Rule { vendors: &["exim"], products: &["exim"], packages: &["exim"], prefixes: &["exim4"], images: &[] },
    Rule { vendors: &["openssl"], products: &["openssl"], packages: &["openssl"], prefixes: &["libssl"], images: &[] },
    Rule { vendors: &["red hat", "polkit", "freedesktop"], products: &["polkit"], packages: &["policykit-1", "polkit", "polkitd"], prefixes: &[], images: &[] },
    Rule { vendors: &["xz", "tukaani"], products: &["xz"], packages: &["xz-utils", "xz"], prefixes: &["liblzma"], images: &[] },
    Rule { vendors: &["openprinting", "cups"], products: &["cups"], packages: &["cups", "cups-browsed", "cups-filters"], prefixes: &[], images: &[] },
    Rule { vendors: &["docker"], products: &["docker", "engine"], packages: &["docker.io", "docker-ce", "docker"], prefixes: &[], images: &[] },
    Rule { vendors: &["jenkins"], products: &["jenkins"], packages: &["jenkins"], prefixes: &[], images: &["jenkins"] },
    Rule { vendors: &["gitlab"], products: &["gitlab"], packages: &["gitlab-ce", "gitlab-ee"], prefixes: &[], images: &["gitlab-ce", "gitlab-ee"] },
    Rule { vendors: &["grafana"], products: &["grafana"], packages: &["grafana"], prefixes: &[], images: &["grafana"] },
    Rule { vendors: &["roundcube"], products: &["roundcube"], packages: &["roundcube", "roundcube-core"], prefixes: &[], images: &["roundcubemail"] },
];

/// An installed package on a saved host, as collected by its last patch scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPkg {
    pub host_id: i64,
    pub host: String,
    pub os_id: Option<String>,
    pub os_version: Option<String>,
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_version: String,
}

/// One saved host that has the product installed and is not known to be fixed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostMatch {
    pub host_id: i64,
    pub host: String,
    /// The package or container image that matched.
    pub source: String,
    pub version: String,
    /// The host has a pending update for this product.
    pub update_pending: bool,
    /// `patch`: the installed version is older than the fixed one. `nofix`: the tracker
    /// lists the package as affected with no fix released. `unchecked`: no tracker data
    /// for this host, so only the product is known to be installed.
    pub status: String,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Affected {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub known_ransomware: bool,
    pub hosts: Vec<HostMatch>,
}

fn rule_for(vendor: &str, product: &str) -> Option<&'static Rule> {
    let v = vendor.to_lowercase();
    let p = product.to_lowercase();
    RULES
        .iter()
        .find(|r| r.vendors.iter().any(|t| v.contains(t)) && r.products.iter().any(|t| p.contains(t)))
}

/// CVE IDs in the catalog for products QuietKeep can match, so the trackers are only
/// asked about those.
pub fn trackable_cves(catalog: &Catalog) -> Vec<String> {
    catalog
        .vulnerabilities
        .iter()
        .filter(|v| rule_for(&v.vendor_project, &v.product).is_some())
        .map(|v| v.cve_id.clone())
        .collect()
}

fn image_name(image: &str) -> &str {
    let no_digest = image.split('@').next().unwrap_or(image);
    let last = no_digest.rsplit('/').next().unwrap_or(no_digest);
    last.split(':').next().unwrap_or(last)
}

/// The tracker source package and version for an installed package. Signed kernels are
/// tracked under the kernel source and carry the kernel's version in the binary package.
fn tracked_source(p: &HostPkg) -> (String, String) {
    if let Some(rest) = p.source.strip_prefix("linux-signed-") {
        let src = if p.os_id.as_deref() == Some("debian") { "linux".to_string() } else { format!("linux-{rest}") };
        return (src, p.version.clone());
    }
    (p.source.clone(), p.source_version.clone())
}

fn rank(status: &str) -> u8 {
    match status {
        "patch" => 3,
        "nofix" => 2,
        _ => 1,
    }
}

/// Checks one host package against the tracker data for one CVE. `None` means the host
/// is fixed or its release is not affected.
fn evaluate(p: &HostPkg, cve: &str, osv: Option<&OsvCache>) -> Option<(String, Option<String>)> {
    let unchecked = Some(("unchecked".to_string(), None));
    let Some(entries) = osv.and_then(|c| c.cves.get(cve)) else { return unchecked };
    let ecos = ecosystems(p.os_id.as_deref(), p.os_version.as_deref());
    if ecos.is_empty() || p.source.starts_with("proxmox-kernel") || p.source.starts_with("pve-kernel") {
        return unchecked;
    }
    let (src, installed) = tracked_source(p);
    let mut result: Option<(String, Option<String>)> = None;
    for e in entries.iter().filter(|e| e.package == src && ecos.contains(&e.ecosystem)) {
        let next = match &e.fixed {
            None => ("nofix".to_string(), None),
            Some(f) if debversion::compare(&installed, f) == Ordering::Less => ("patch".to_string(), Some(f.clone())),
            Some(_) => continue,
        };
        if result.as_ref().is_none_or(|r| rank(&next.0) > rank(&r.0)) {
            result = Some(next);
        }
    }
    result
}

/// Images are (host id, host name, image reference). Pending is (host id, package).
/// Only hosts present in these lists are checked, so the result always follows the
/// saved host list. Without tracker data every product match is `unchecked`.
pub fn affected(
    catalog: &Catalog,
    packages: &[HostPkg],
    images: &[(i64, String, String)],
    pending: &[(i64, String)],
    osv: Option<&OsvCache>,
) -> Vec<Affected> {
    let mut out = Vec::new();
    for v in &catalog.vulnerabilities {
        let Some(rule) = rule_for(&v.vendor_project, &v.product) else { continue };
        let matches = |name: &str| rule.packages.contains(&name) || rule.prefixes.iter().any(|p| name.starts_with(p));
        let pending_on = |id: i64| pending.iter().any(|(h, n)| *h == id && matches(n));
        let mut hosts: Vec<HostMatch> = Vec::new();
        for p in packages.iter().filter(|p| matches(&p.name)) {
            let Some((status, fixed_version)) = evaluate(p, &v.cve_id, osv) else { continue };
            let m = HostMatch {
                host_id: p.host_id,
                host: p.host.clone(),
                source: p.name.clone(),
                version: p.version.clone(),
                update_pending: pending_on(p.host_id),
                status,
                fixed_version,
            };
            match hosts.iter_mut().find(|h| h.host_id == p.host_id) {
                Some(h) if rank(&m.status) > rank(&h.status) => *h = m,
                Some(_) => {}
                None => hosts.push(m),
            }
        }
        for (id, host, image) in images {
            if rule.images.contains(&image_name(image)) && !hosts.iter().any(|h| h.host_id == *id && h.source == *image) {
                let version = image.rsplit_once(':').map(|(_, t)| t.to_string()).unwrap_or_default();
                hosts.push(HostMatch {
                    host_id: *id,
                    host: host.clone(),
                    source: image.clone(),
                    version,
                    update_pending: false,
                    status: "unchecked".into(),
                    fixed_version: None,
                });
            }
        }
        if !hosts.is_empty() {
            out.push(Affected {
                cve_id: v.cve_id.clone(),
                vendor_project: v.vendor_project.clone(),
                product: v.product.clone(),
                vulnerability_name: v.vulnerability_name.clone(),
                date_added: v.date_added.clone(),
                known_ransomware: v.ransomware(),
                hosts,
            });
        }
    }
    out.sort_by(|a, b| b.date_added.cmp(&a.date_added));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::OsvEntry;
    use crate::Vulnerability;

    fn vuln(id: &str, vendor: &str, product: &str) -> Vulnerability {
        Vulnerability {
            cve_id: id.into(),
            vendor_project: vendor.into(),
            product: product.into(),
            vulnerability_name: String::new(),
            date_added: "2026-01-01".into(),
            short_description: String::new(),
            required_action: String::new(),
            due_date: String::new(),
            known_ransomware_campaign_use: String::new(),
            notes: String::new(),
        }
    }

    fn pkg(id: i64, os: &str, ver: &str, name: &str, version: &str, source: &str) -> HostPkg {
        HostPkg {
            host_id: id,
            host: format!("h{id}"),
            os_id: Some(os.into()),
            os_version: Some(ver.into()),
            name: name.into(),
            version: version.into(),
            source: source.into(),
            source_version: version.into(),
        }
    }

    fn entry(eco: &str, package: &str, fixed: Option<&str>) -> OsvEntry {
        OsvEntry { ecosystem: eco.into(), package: package.into(), fixed: fixed.map(str::to_string) }
    }

    #[test]
    fn tracker_versions_decide_what_needs_patching() {
        let catalog = Catalog {
            catalog_version: "1".into(),
            date_released: "x".into(),
            vulnerabilities: vec![
                vuln("CVE-2024-1086", "Linux", "Kernel"),
                vuln("CVE-2021-3156", "Sudo", "Sudo"),
                vuln("CVE-2021-23017", "F5", "Nginx"),
                vuln("CVE-2023-0001", "Microsoft", "Windows"),
            ],
        };
        let packages = vec![
            pkg(1, "ubuntu", "22.04", "linux-image-6.8.0-1060-aws", "6.8.0-1060.63~22.04.1", "linux-signed-aws-6.8"),
            pkg(1, "ubuntu", "22.04", "sudo", "1.9.9-1ubuntu2.4", "sudo"),
            pkg(2, "debian", "13", "sudo", "1.9.16p2-3", "sudo"),
            pkg(2, "debian", "13", "linux-image-6.12.57+deb13-amd64", "6.12.57-1", "linux-signed-amd64"),
            pkg(3, "kali", "2026.3", "sudo", "1.9.16", "sudo"),
            pkg(4, "debian", "13", "proxmox-kernel-6.14.8-2-pve-signed", "6.14.8-2", "proxmox-kernel-6.14.8-2"),
        ];
        let mut cache = OsvCache::default();
        cache.cves.insert(
            "CVE-2021-3156".into(),
            vec![entry("Ubuntu:22.04:LTS", "sudo", Some("1.9.9-1ubuntu2.5")), entry("Debian:13", "sudo", Some("1.9.5p2-1"))],
        );
        cache.cves.insert(
            "CVE-2024-1086".into(),
            vec![entry("Debian:13", "linux", Some("6.6.15-1")), entry("Ubuntu:22.04:LTS", "linux-aws-6.8", None)],
        );
        let images = vec![(5, "c".to_string(), "nginx:1.27-alpine".to_string())];
        let r = affected(&catalog, &packages, &images, &[(1, "sudo".into())], Some(&cache));
        let sudo = r.iter().find(|a| a.cve_id == "CVE-2021-3156").unwrap();
        assert_eq!(sudo.hosts.len(), 2);
        assert_eq!(sudo.hosts[0].status, "patch");
        assert_eq!(sudo.hosts[0].fixed_version.as_deref(), Some("1.9.9-1ubuntu2.5"));
        assert!(sudo.hosts[0].update_pending);
        assert_eq!(sudo.hosts[1].host_id, 3);
        assert_eq!(sudo.hosts[1].status, "unchecked");
        let kernel = r.iter().find(|a| a.cve_id == "CVE-2024-1086").unwrap();
        let st: Vec<(i64, &str)> = kernel.hosts.iter().map(|h| (h.host_id, h.status.as_str())).collect();
        assert_eq!(st, vec![(1, "nofix"), (4, "unchecked")]);
        assert_eq!(r.iter().find(|a| a.cve_id == "CVE-2021-23017").unwrap().hosts[0].status, "unchecked");
        assert!(affected(&catalog, &[], &[], &[], Some(&cache)).is_empty());
        assert_eq!(trackable_cves(&catalog).len(), 3);
        let none = affected(&catalog, &packages, &[], &[], None);
        assert!(none.iter().all(|a| a.hosts.iter().all(|h| h.status == "unchecked")));
    }
}
