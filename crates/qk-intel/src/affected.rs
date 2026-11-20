//! Matches catalog entries to the software installed on saved hosts. The catalog lists
//! products, not version ranges, so a match means the product is installed and the host's
//! security updates should be checked. It does not prove the host is vulnerable.

use serde::Serialize;

use crate::Catalog;

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

/// One saved host that has the product installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostMatch {
    pub host_id: i64,
    pub host: String,
    /// The package or container image that matched.
    pub source: String,
    pub version: String,
    /// The host has a pending update for this product.
    pub update_pending: bool,
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

fn image_name(image: &str) -> &str {
    let no_digest = image.split('@').next().unwrap_or(image);
    let last = no_digest.rsplit('/').next().unwrap_or(no_digest);
    last.split(':').next().unwrap_or(last)
}

/// Packages are (host id, host name, package, version). Images are (host id, host name,
/// image reference). Only hosts present in these lists are checked, so the result always
/// follows the saved host list.
pub fn affected(
    catalog: &Catalog,
    packages: &[(i64, String, String, String)],
    images: &[(i64, String, String)],
    pending: &[(i64, String)],
) -> Vec<Affected> {
    let mut out = Vec::new();
    for v in &catalog.vulnerabilities {
        let Some(rule) = rule_for(&v.vendor_project, &v.product) else { continue };
        let matches = |name: &str| rule.packages.contains(&name) || rule.prefixes.iter().any(|p| name.starts_with(p));
        let pending_on = |id: i64| pending.iter().any(|(h, n)| *h == id && matches(n));
        let mut hosts: Vec<HostMatch> = Vec::new();
        for (id, host, name, version) in packages {
            if matches(name) {
                if hosts.iter().any(|h| h.host_id == *id) {
                    continue;
                }
                hosts.push(HostMatch {
                    host_id: *id,
                    host: host.clone(),
                    source: name.clone(),
                    version: version.clone(),
                    update_pending: pending_on(*id),
                });
            }
        }
        for (id, host, image) in images {
            if rule.images.contains(&image_name(image)) && !hosts.iter().any(|h| h.host_id == *id && h.source == *image) {
                let version = image.rsplit_once(':').map(|(_, t)| t.to_string()).unwrap_or_default();
                hosts.push(HostMatch { host_id: *id, host: host.clone(), source: image.clone(), version, update_pending: false });
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

    #[test]
    fn matches_follow_installed_software() {
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
            (1, "a".to_string(), "linux-image-6.12.0-1-amd64".to_string(), "6.12.1".to_string()),
            (1, "a".to_string(), "linux-image-6.12.0-2-amd64".to_string(), "6.12.2".to_string()),
            (2, "b".to_string(), "sudo".to_string(), "1.9.16".to_string()),
        ];
        let images = vec![(3, "c".to_string(), "nginx:1.27-alpine".to_string())];
        let pending = vec![(2, "sudo".to_string())];
        let r = affected(&catalog, &packages, &images, &pending);
        assert_eq!(r.len(), 3);
        let kernel = r.iter().find(|a| a.cve_id == "CVE-2024-1086").unwrap();
        assert_eq!(kernel.hosts.len(), 1);
        assert_eq!(r.iter().find(|a| a.cve_id == "CVE-2021-23017").unwrap().hosts[0].version, "1.27-alpine");
        assert!(r.iter().find(|a| a.cve_id == "CVE-2021-3156").unwrap().hosts[0].update_pending);
        assert!(!kernel.hosts[0].update_pending);
        assert!(affected(&catalog, &[], &[], &[]).is_empty());
    }
}
