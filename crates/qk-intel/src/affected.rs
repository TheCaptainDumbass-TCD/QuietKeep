//! Matches catalog entries to the software installed on saved hosts. The catalog lists
//! products, not version ranges, so a match means the product is installed and the host's
//! security updates should be checked. It does not prove the host is vulnerable.

use serde::Serialize;

use crate::osv::{debian_testing, ecosystems, ubuntu_release, OsvCache, OsvEntry};
use crate::Catalog;
use qk_core::debversion;
use std::cmp::Ordering;
use std::collections::BTreeSet;

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
    /// for this host, so only the product is known to be installed. `minor`: the
    /// distribution rates it unimportant, usually because its build is not exploitable.
    pub status: String,
    pub fixed_version: Option<String>,
    /// For `waiting`, the distribution that has not shipped the upstream fix yet.
    pub waiting_on: Option<String>,
}

/// What a Proxmox host's kernel changelog says about its running kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKernel {
    pub host_id: i64,
    /// `uname -r`, such as `7.0.14-30-pve`.
    pub running: String,
    /// The Ubuntu kernel it is built on, such as `7.0.0-44.44`.
    pub ubuntu_base: Option<String>,
    /// CVEs the changelog names as fixed.
    pub fixed_cves: BTreeSet<String>,
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
        let src = if p.os_id.as_deref() == Some("ubuntu") { format!("linux-{rest}") } else { "linux".to_string() };
        return (src, p.version.clone());
    }
    (p.source.clone(), p.source_version.clone())
}

fn rank(status: &str) -> u8 {
    match status {
        "patch" => 4,
        "waiting" => 3,
        "nofix" => 2,
        "unchecked" => 1,
        _ => 0,
    }
}

struct Ctx<'a> {
    osv: Option<&'a OsvCache>,
    testing: Option<String>,
    /// Each Proxmox kernel with the Ubuntu release it is built on.
    kernels: Vec<(&'a HostKernel, Option<String>)>,
}

fn is_proxmox_kernel(p: &HostPkg) -> bool {
    p.source.starts_with("proxmox-kernel") || p.source.starts_with("pve-kernel")
}

/// The distribution a host waits on when upstream has a fix it does not ship yet. Debian
/// and Ubuntu hosts are not listed: a fix they lack is installed by patching.
fn downstream(p: &HostPkg) -> Option<&'static str> {
    if is_proxmox_kernel(p) {
        return Some("Proxmox");
    }
    match p.os_id.as_deref() {
        Some("kali") => Some("Kali"),
        Some("parrot") => Some("Parrot"),
        _ => None,
    }
}

/// Checks one host package against the tracker data for one CVE. `None` means the host
/// is fixed or its release is not affected.
fn evaluate(p: &HostPkg, cve: &str, ctx: &Ctx) -> Option<(String, Option<String>)> {
    let unchecked = Some(("unchecked".to_string(), None));
    let Some(entries) = ctx.osv.and_then(|c| c.cves.get(cve)) else { return unchecked };
    if is_proxmox_kernel(p) {
        return proxmox_kernel(p, cve, entries, ctx);
    }
    let ecos = ecosystems(p.os_id.as_deref(), p.os_version.as_deref(), ctx.testing.as_deref());
    if ecos.is_empty() {
        return unchecked;
    }
    let (src, installed) = tracked_source(p);
    tracker_status(entries, &src, &installed, &ecos)
}

/// Compares an installed version with the tracker entries for each ecosystem in priority
/// order. A fix in any of them counts. Otherwise the first ecosystem with an entry decides.
fn tracker_status(entries: &[OsvEntry], src: &str, installed: &str, ecos: &[String]) -> Option<(String, Option<String>)> {
    let mut result: Option<(String, Option<String>)> = None;
    for eco in ecos {
        let mut found: Option<(String, Option<String>)> = None;
        for e in entries.iter().filter(|e| e.package == src && e.ecosystem == *eco) {
            let minor = e.urgency.as_deref().is_some_and(|u| u.starts_with("unimportant"));
            let next = match &e.fixed {
                None if minor => ("minor".to_string(), None),
                None => ("nofix".to_string(), None),
                Some(f) if debversion::compare(installed, f) == Ordering::Less => {
                    (if minor { "minor" } else { "patch" }.to_string(), Some(f.clone()))
                }
                Some(_) => return None,
            };
            if found.as_ref().is_none_or(|r| rank(&next.0) > rank(&r.0)) {
                found = Some(next);
            }
        }
        if result.is_none() {
            result = found;
        }
    }
    result
}

/// Proxmox kernels are Ubuntu kernels with Proxmox patches. Only the running kernel is
/// exposed, so other installed kernels are skipped. A CVE named in the running kernel's
/// changelog is fixed. Otherwise its Ubuntu base is compared with Ubuntu's fix.
fn proxmox_kernel(p: &HostPkg, cve: &str, entries: &[OsvEntry], ctx: &Ctx) -> Option<(String, Option<String>)> {
    let unchecked = Some(("unchecked".to_string(), None));
    let Some((k, eco)) = ctx.kernels.iter().find(|(k, _)| k.host_id == p.host_id) else { return unchecked };
    let r = &k.running;
    let running = [format!("proxmox-kernel-{r}-signed"), format!("proxmox-kernel-{r}"), format!("pve-kernel-{r}")];
    if !running.contains(&p.name) {
        return None;
    }
    if k.fixed_cves.contains(cve) {
        return None;
    }
    let (Some(base), Some(eco)) = (k.ubuntu_base.as_deref(), eco) else { return unchecked };
    tracker_status(entries, "linux", base, std::slice::from_ref(eco))
        .map(|(status, fixed)| (status, fixed.map(|f| format!("Ubuntu kernel {f}"))))
}

/// Images are (host id, host name, image reference). Pending is (host id, package).
/// Only hosts present in these lists are checked, so the result always follows the
/// saved host list. Without tracker data every product match is `unchecked`.
pub fn affected(
    catalog: &Catalog,
    packages: &[HostPkg],
    images: &[(i64, String, String)],
    pending: &[(i64, String)],
    kernels: &[HostKernel],
    osv: Option<&OsvCache>,
) -> Vec<Affected> {
    let ctx = Ctx {
        osv,
        testing: osv.and_then(debian_testing),
        kernels: kernels
            .iter()
            .map(|k| (k, k.ubuntu_base.as_deref().zip(osv).and_then(|(b, c)| ubuntu_release(b, c))))
            .collect(),
    };
    let mut out = Vec::new();
    for v in &catalog.vulnerabilities {
        let Some(rule) = rule_for(&v.vendor_project, &v.product) else { continue };
        let matches = |name: &str| rule.packages.contains(&name) || rule.prefixes.iter().any(|p| name.starts_with(p));
        let pending_on = |id: i64| pending.iter().any(|(h, n)| *h == id && matches(n));
        let mut hosts: Vec<HostMatch> = Vec::new();
        for p in packages.iter().filter(|p| matches(&p.name)) {
            let Some((mut status, fixed_version)) = evaluate(p, &v.cve_id, &ctx) else { continue };
            let update_pending = pending_on(p.host_id);
            let mut waiting_on = None;
            if status == "patch" && !update_pending {
                if let Some(d) = downstream(p) {
                    status = "waiting".into();
                    waiting_on = Some(d.to_string());
                }
            }
            let m = HostMatch {
                host_id: p.host_id,
                host: p.host.clone(),
                source: p.name.clone(),
                version: p.version.clone(),
                update_pending,
                status,
                fixed_version,
                waiting_on,
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
                    waiting_on: None,
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
        OsvEntry { ecosystem: eco.into(), package: package.into(), fixed: fixed.map(str::to_string), urgency: None }
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
            vec![entry("Ubuntu:22.04:LTS", "sudo", Some("1.9.9-1ubuntu2.5")), entry("Debian:13", "sudo", Some("1.9.5p2-1")), entry("Debian:14", "sudo", Some("1.9.17-1"))],
        );
        cache.cves.insert(
            "CVE-2024-1086".into(),
            vec![entry("Debian:13", "linux", Some("6.6.15-1")), entry("Ubuntu:22.04:LTS", "linux-aws-6.8", None)],
        );
        let images = vec![(5, "c".to_string(), "nginx:1.27-alpine".to_string())];
        let r = affected(&catalog, &packages, &images, &[(1, "sudo".into())], &[], Some(&cache));
        let sudo = r.iter().find(|a| a.cve_id == "CVE-2021-3156").unwrap();
        assert_eq!(sudo.hosts.len(), 2);
        assert_eq!(sudo.hosts[0].status, "patch");
        assert_eq!(sudo.hosts[0].fixed_version.as_deref(), Some("1.9.9-1ubuntu2.5"));
        assert!(sudo.hosts[0].update_pending);
        assert_eq!(sudo.hosts[1].host_id, 3);
        assert_eq!(sudo.hosts[1].status, "waiting");
        assert_eq!(sudo.hosts[1].waiting_on.as_deref(), Some("Kali"));
        let kernel = r.iter().find(|a| a.cve_id == "CVE-2024-1086").unwrap();
        let st: Vec<(i64, &str)> = kernel.hosts.iter().map(|h| (h.host_id, h.status.as_str())).collect();
        assert_eq!(st, vec![(1, "nofix"), (4, "unchecked")]);
        assert_eq!(r.iter().find(|a| a.cve_id == "CVE-2021-23017").unwrap().hosts[0].status, "unchecked");
        assert!(affected(&catalog, &[], &[], &[], &[], Some(&cache)).is_empty());
        let mut minor = cache.clone();
        minor.cves.get_mut("CVE-2021-3156").unwrap()[0].urgency = Some("unimportant".into());
        let r = affected(&catalog, &packages, &[], &[], &[], Some(&minor));
        assert_eq!(r.iter().find(|a| a.cve_id == "CVE-2021-3156").unwrap().hosts[0].status, "minor");
        assert_eq!(trackable_cves(&catalog).len(), 3);
        let none = affected(&catalog, &packages, &[], &[], &[], None);
        assert!(none.iter().all(|a| a.hosts.iter().all(|h| h.status == "unchecked")));
    }

    #[test]
    fn derivatives_follow_their_upstream_trackers() {
        let catalog = Catalog {
            catalog_version: "1".into(),
            date_released: "x".into(),
            vulnerabilities: vec![
                vuln("CVE-2026-0001", "Linux", "Kernel"),
                vuln("CVE-2026-0002", "Linux", "Kernel"),
                vuln("CVE-2026-0003", "Linux", "Kernel"),
                vuln("CVE-2021-3156", "Sudo", "Sudo"),
            ],
        };
        let pve = |id: i64, name: &str, version: &str| HostPkg {
            source: name.trim_end_matches("-signed").into(),
            ..pkg(id, "debian", "13", name, version, "")
        };
        let packages = vec![
            pve(1, "proxmox-kernel-7.0.14-30-pve-signed", "7.0.14-30"),
            pve(1, "proxmox-kernel-7.0.14-29-pve-signed", "7.0.14-29"),
            pve(2, "proxmox-kernel-7.0.14-30-pve-signed", "7.0.14-30"),
            pve(3, "proxmox-kernel-6.5.13-6-pve-signed", "6.5.13-6"),
            pkg(4, "parrot", "7.4", "sudo", "1.9.16p2-3+deb13u5", "sudo"),
            pkg(4, "parrot", "7.4", "linux-image-7.1.13+parrot7-amd64", "7.1.13-1parrot1", "linux"),
            pkg(5, "kali", "2026.3", "linux-image-7.2.15+kali-amd64", "7.2.15-1kali1", "linux"),
            pkg(6, "parrot", "7.4", "parrot-core", "7.4", "parrot-core"),
        ];
        let mut cache = OsvCache::default();
        cache.cves.insert(
            "CVE-2026-0001".into(),
            vec![entry("Ubuntu:26.04:LTS", "linux", Some("7.0.0-45.45")), entry("Debian:13", "linux", None), entry("Debian:14", "linux", Some("7.2.10-1"))],
        );
        cache.cves.insert("CVE-2026-0002".into(), vec![entry("Ubuntu:26.04:LTS", "linux", Some("7.0.0-44.44"))]);
        cache.cves.insert("CVE-2026-0003".into(), vec![entry("Ubuntu:26.04:LTS", "linux", None)]);
        cache.cves.insert("CVE-2021-3156".into(), vec![entry("Debian:13", "sudo", Some("1.9.16p2-3+deb13u5"))]);
        let kernel = |id: i64, cves: &[&str]| HostKernel {
            host_id: id,
            running: "7.0.14-30-pve".into(),
            ubuntu_base: Some("7.0.0-44.44".into()),
            fixed_cves: cves.iter().map(|c| c.to_string()).collect(),
        };
        let kernels = vec![kernel(1, &[]), kernel(2, &["CVE-2026-0001"])];
        let pending = vec![(1, "proxmox-kernel-7.0".to_string())];
        let r = affected(&catalog, &packages, &[], &pending, &kernels, Some(&cache));
        let hosts = |cve: &str| -> Vec<(i64, String, Option<String>)> {
            r.iter()
                .find(|a| a.cve_id == cve)
                .map(|a| a.hosts.iter().map(|h| (h.host_id, h.status.clone(), h.fixed_version.clone())).collect())
                .unwrap_or_default()
        };
        let s = |st: &str| st.to_string();
        assert_eq!(
            hosts("CVE-2026-0001"),
            vec![
                (1, s("patch"), Some(s("Ubuntu kernel 7.0.0-45.45"))),
                (3, s("unchecked"), None),
                (4, s("nofix"), None),
            ]
        );
        assert_eq!(hosts("CVE-2026-0002"), vec![(3, s("unchecked"), None)]);
        let nofix = hosts("CVE-2026-0003");
        assert_eq!(nofix[0], (1, s("nofix"), None));
        assert_eq!(nofix[1], (2, s("nofix"), None));
        assert!(r.iter().all(|a| a.hosts.iter().all(|h| h.source != "proxmox-kernel-7.0.14-29-pve-signed")));
        assert!(hosts("CVE-2021-3156").is_empty());
        let mut later = cache.clone();
        later.cves.get_mut("CVE-2026-0001").unwrap()[2].fixed = Some("7.3.1-1".into());
        let r = affected(&catalog, &packages, &[], &[], &kernels, Some(&later));
        let a = r.iter().find(|a| a.cve_id == "CVE-2026-0001").unwrap();
        let kali = a.hosts.iter().find(|h| h.host_id == 5).unwrap();
        assert_eq!((kali.status.as_str(), kali.waiting_on.as_deref()), ("waiting", Some("Kali")));
        let pve = a.hosts.iter().find(|h| h.host_id == 1).unwrap();
        assert_eq!((pve.status.as_str(), pve.waiting_on.as_deref()), ("waiting", Some("Proxmox")));
    }
}
