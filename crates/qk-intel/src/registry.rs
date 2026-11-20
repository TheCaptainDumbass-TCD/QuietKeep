//! Read-only container registry lookups: tag lists and manifest digests.
//! Anonymous only. Nothing is pulled. Call only after the user has allowed registry checks.

use std::collections::HashMap;
use std::time::Duration;

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json, \
application/vnd.docker.distribution.manifest.v2+json, \
application/vnd.oci.image.manifest.v1+json";
const MAX_TAG_PAGES: usize = 20;
const MAX_PROBES: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Registry host used for API calls, e.g. `registry-1.docker.io` or `ghcr.io`.
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: Option<String>,
}

/// Parses an image reference such as `postgres:16`, `ghcr.io/open-webui/open-webui:v0.12.3`
/// or `valkey/valkey:9@sha256:...`.
pub fn parse_ref(reference: &str) -> Option<ImageRef> {
    let reference = reference.trim();
    if reference.is_empty() {
        return None;
    }
    let (name, digest) = match reference.split_once('@') {
        Some((n, d)) => (n, Some(d.to_string())),
        None => (reference, None),
    };
    let slash = name.rfind('/');
    let (name, tag) = match name.rfind(':') {
        Some(c) if slash.is_none_or(|s| c > s) => (&name[..c], name[c + 1..].to_string()),
        _ => (name, "latest".to_string()),
    };
    let (registry, repository) = match name.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (first.to_string(), rest.to_string())
        }
        _ => ("docker.io".to_string(), name.to_string()),
    };
    let (registry, repository) = if registry == "docker.io" || registry == "index.docker.io" {
        let repo = if repository.contains('/') { repository } else { format!("library/{repository}") };
        ("registry-1.docker.io".to_string(), repo)
    } else {
        (registry, repository)
    };
    if tag.is_empty() || repository.is_empty() {
        return None;
    }
    Some(ImageRef { registry, repository, tag, digest })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    prefix: String,
    nums: Vec<u64>,
    suffix: String,
}

fn parse_version(tag: &str) -> Option<Version> {
    let start = tag.find(|c: char| c.is_ascii_digit())?;
    let prefix = &tag[..start];
    if !(prefix.is_empty() || prefix == "v" || prefix == "V") {
        return None;
    }
    let rest = &tag[start..];
    let bytes = rest.as_bytes();
    let mut nums = Vec::new();
    let mut i = 0;
    loop {
        let begin = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        nums.push(rest[begin..i].parse().ok()?);
        if i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
            i += 1;
        } else {
            break;
        }
    }
    Some(Version { prefix: prefix.to_string(), nums, suffix: rest[i..].to_string() })
}

/// Newer releases of the same kind of tag: same prefix, same suffix and the same number of parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewerTags {
    /// Newest tag in the current major series (same first number).
    pub same_series: Option<String>,
    /// Newest tag overall, when it is in a higher major series.
    pub major: Option<String>,
}

pub fn newer_tags(current: &str, tags: &[String]) -> NewerTags {
    let Some(cur) = parse_version(current) else { return NewerTags::default() };
    let mut best_series: Option<(Vec<u64>, &String)> = None;
    let mut best_any: Option<(Vec<u64>, &String)> = None;
    for t in tags {
        let Some(v) = parse_version(t) else { continue };
        if v.prefix != cur.prefix || v.suffix != cur.suffix || v.nums.len() != cur.nums.len() || v.nums <= cur.nums {
            continue;
        }
        if v.nums[0] == cur.nums[0] && best_series.as_ref().is_none_or(|(b, _)| v.nums > *b) {
            best_series = Some((v.nums.clone(), t));
        }
        if best_any.as_ref().is_none_or(|(b, _)| v.nums > *b) {
            best_any = Some((v.nums, t));
        }
    }
    NewerTags {
        same_series: best_series.map(|(_, t)| t.clone()),
        major: best_any.filter(|(n, _)| n[0] != cur.nums[0]).map(|(_, t)| t.clone()),
    }
}

/// Database images whose on-disk format can change between major versions.
pub fn is_database(repository: &str) -> bool {
    let name = repository.rsplit('/').next().unwrap_or(repository);
    name.contains("postgres") || name.contains("postgis") || ["mysql", "mariadb", "mongo", "timescaledb"].contains(&name)
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("{0}")]
    Http(String),
    #[error("the registry requires a login")]
    Unauthorized,
    #[error("the image was not found in the registry")]
    NotFound,
    #[error("the registry is limiting requests from this network")]
    RateLimited,
}

pub type Result<T> = std::result::Result<T, RegistryError>;

/// One registry session for a scan: reuses HTTP connections and bearer tokens.
pub struct Client {
    agent: ureq::Agent,
    tokens: HashMap<(String, String), Option<String>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

fn http(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Http(e.to_string())
}

fn challenge_param(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let end = header[start..].find('"')? + start;
    Some(header[start..end].to_string())
}

impl Client {
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .user_agent(concat!("QuietKeep/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent, tokens: HashMap::new() }
    }

    fn token(&mut self, image: &ImageRef) -> Result<Option<String>> {
        let key = (image.registry.clone(), image.repository.clone());
        if let Some(t) = self.tokens.get(&key) {
            return Ok(t.clone());
        }
        let resp = self.agent.get(&format!("https://{}/v2/", image.registry)).call().map_err(http)?;
        let token = if resp.status() == 401 {
            let header = resp
                .headers()
                .get("www-authenticate")
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let realm = challenge_param(&header, "realm").ok_or(RegistryError::Unauthorized)?;
            let mut req = self.agent.get(&realm).query("scope", format!("repository:{}:pull", image.repository));
            if let Some(service) = challenge_param(&header, "service") {
                req = req.query("service", service);
            }
            let mut resp = req.call().map_err(http)?;
            if resp.status() != 200 {
                return Err(RegistryError::Unauthorized);
            }
            let body: serde_json::Value =
                serde_json::from_str(&resp.body_mut().read_to_string().map_err(http)?).map_err(http)?;
            body.get("token").or_else(|| body.get("access_token")).and_then(|t| t.as_str()).map(String::from)
        } else {
            None
        };
        self.tokens.insert(key, token.clone());
        Ok(token)
    }

    fn get(&mut self, image: &ImageRef, url: &str, head: bool) -> Result<ureq::http::Response<ureq::Body>> {
        let token = self.token(image)?;
        let resp = if head {
            let mut req = self.agent.head(url).header("Accept", ACCEPT);
            if let Some(t) = &token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            req.call()
        } else {
            let mut req = self.agent.get(url).header("Accept", ACCEPT);
            if let Some(t) = &token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            req.call()
        }
        .map_err(http)?;
        match resp.status().as_u16() {
            200 => Ok(resp),
            401 | 403 => Err(RegistryError::Unauthorized),
            404 => Err(RegistryError::NotFound),
            429 => Err(RegistryError::RateLimited),
            s => Err(RegistryError::Http(format!("registry answered {s}"))),
        }
    }

    /// Digest the registry currently serves for the image's tag.
    pub fn tag_digest(&mut self, image: &ImageRef) -> Result<String> {
        let url = format!("https://{}/v2/{}/manifests/{}", image.registry, image.repository, image.tag);
        let resp = self.get(image, &url, true)?;
        resp.headers()
            .get("docker-content-digest")
            .and_then(|h| h.to_str().ok())
            .map(String::from)
            .ok_or_else(|| RegistryError::Http("the registry sent no digest".into()))
    }

    /// Tags of the image's repository, following pagination up to a limit. The flag is true
    /// when the list was cut short because the repository has more tags than the limit.
    pub fn tags(&mut self, image: &ImageRef) -> Result<(Vec<String>, bool)> {
        let mut url = format!("https://{}/v2/{}/tags/list?n=1000", image.registry, image.repository);
        let mut all = Vec::new();
        for page in 0..MAX_TAG_PAGES {
            let mut resp = self.get(image, &url, false)?;
            let next = resp
                .headers()
                .get("link")
                .and_then(|h| h.to_str().ok())
                .and_then(|l| l.split_once('<').and_then(|(_, r)| r.split_once('>')).map(|(u, _)| u.to_string()));
            let body: serde_json::Value =
                serde_json::from_str(&resp.body_mut().read_to_string().map_err(http)?).map_err(http)?;
            if let Some(tags) = body.get("tags").and_then(|t| t.as_array()) {
                all.extend(tags.iter().filter_map(|t| t.as_str().map(String::from)));
            }
            match next {
                Some(_) if page + 1 == MAX_TAG_PAGES => return Ok((all, true)),
                Some(n) if n.starts_with('/') => url = format!("https://{}{}", image.registry, n),
                Some(n) => url = n,
                None => break,
            }
        }
        Ok((all, false))
    }

    fn exists(&mut self, image: &ImageRef, tag: &str) -> bool {
        let url = format!("https://{}/v2/{}/manifests/{tag}", image.registry, image.repository);
        self.get(image, &url, true).is_ok()
    }

    /// Finds newer releases by asking for the next version numbers directly. Used when a
    /// repository has too many tags to list, such as projects that tag every build.
    pub fn probe_newer(&mut self, image: &ImageRef) -> Vec<String> {
        let Some(cur) = parse_version(&image.tag) else { return Vec::new() };
        let fmt = |n: &[u64]| {
            format!("{}{}{}", cur.prefix, n.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("."), cur.suffix)
        };
        let mut found = Vec::new();
        let mut best = cur.nums.clone();
        let mut level = best.len() - 1;
        for _ in 0..MAX_PROBES {
            let mut next = best.clone();
            next[level] += 1;
            for x in next.iter_mut().skip(level + 1) {
                *x = 0;
            }
            let tag = fmt(&next);
            if self.exists(image, &tag) {
                found.push(tag);
                best = next;
                level = best.len() - 1;
            } else if level == 0 {
                break;
            } else {
                level -= 1;
            }
        }
        found
    }
}

/// Result of checking one image against its registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub update_available: Option<bool>,
    /// `current`, `rebuild`, `release`, `major`, `pinned-current`, `pinned-behind` or `unknown`.
    pub kind: &'static str,
    pub latest_tag: Option<String>,
    pub major_tag: Option<String>,
    pub note: Option<String>,
}

fn unknown(note: String) -> Assessment {
    Assessment { update_available: None, kind: "unknown", latest_tag: None, major_tag: None, note: Some(note) }
}

/// Compares a running image with its registry: newer releases of the same kind of tag,
/// a rebuilt tag, and for digest pinned images whether the pin has fallen behind.
pub fn assess(client: &mut Client, reference: &str, local_digests: &[String]) -> Assessment {
    let Some(image) = parse_ref(reference) else { return unknown("QuietKeep could not read this image name.".into()) };
    let limited = || {
        if image.registry.ends_with("docker.io") {
            unknown("Docker Hub allows 100 anonymous checks an hour for each network, and that limit is used up. QuietKeep checks again on the next scan.".into())
        } else {
            unknown("The registry is limiting requests from your network. QuietKeep checks again on the next scan.".into())
        }
    };
    let mut tags = match client.tags(&image) {
        Ok((t, false)) => t,
        Ok((mut t, true)) => {
            t.extend(client.probe_newer(&image));
            t
        }
        Err(RegistryError::RateLimited) => return limited(),
        Err(_) => client.probe_newer(&image),
    };
    tags.sort();
    tags.dedup();
    let newer = newer_tags(&image.tag, &tags);
    // The digest is only needed for pinned images and for spotting a rebuilt tag, and on Docker
    // Hub every digest lookup counts against the hourly limit.
    let current = if image.digest.is_some() || newer.same_series.is_none() {
        match client.tag_digest(&image) {
            Ok(d) => d,
            Err(RegistryError::RateLimited) => return limited(),
            Err(e) => return unknown(format!("The registry could not be checked: {e}.")),
        }
    } else {
        String::new()
    };
    let database = is_database(&image.repository);
    let major_note = newer.major.as_ref().map(|m| {
        if database {
            format!("Version {m} is a new major release. Database major upgrades need a data migration, so follow the image's upgrade guide instead of updating in place.")
        } else {
            format!("Version {m} is a new major release. Read its release notes before upgrading.")
        }
    });
    if let Some(pin) = &image.digest {
        let behind = *pin != current;
        let mut note = if behind {
            format!("Pinned to an older build. The {} tag now points to a newer build, so this container is missing the fixes in it. Update the pin in the compose file, or update the app that ships this compose file.", image.tag)
        } else {
            format!("Pinned to a fixed build that is still the newest build of the {} tag.", image.tag)
        };
        if let Some(t) = &newer.same_series {
            note.push_str(&format!(" Release {t} is also available."));
        }
        if let Some(m) = &major_note {
            note.push(' ');
            note.push_str(m);
        }
        return Assessment {
            update_available: Some(behind),
            kind: if behind { "pinned-behind" } else { "pinned-current" },
            latest_tag: newer.same_series,
            major_tag: newer.major,
            note: Some(note),
        };
    }
    let rebuilt = !current.is_empty() && !local_digests.is_empty() && !local_digests.iter().any(|d| d.ends_with(&current));
    if let Some(t) = newer.same_series {
        return Assessment { update_available: Some(true), kind: "release", latest_tag: Some(t), major_tag: newer.major, note: major_note };
    }
    if rebuilt {
        return Assessment { update_available: Some(true), kind: "rebuild", latest_tag: None, major_tag: newer.major, note: major_note };
    }
    if newer.major.is_some() {
        return Assessment { update_available: Some(false), kind: "major", latest_tag: None, major_tag: newer.major, note: major_note };
    }
    if local_digests.is_empty() {
        return unknown("The local image has no registry digest. It was built locally or loaded from a file.".into());
    }
    Assessment { update_available: Some(false), kind: "current", latest_tag: None, major_tag: None, note: None }
}

const CACHE_TTL: Duration = Duration::from_secs(3 * 3600);

type CacheKey = (String, Vec<String>);
static CACHE: std::sync::LazyLock<std::sync::Mutex<HashMap<CacheKey, (std::time::Instant, Assessment)>>> =
    std::sync::LazyLock::new(Default::default);

/// Like [`assess`], but reuses a successful answer for three hours so scheduled scans stay
/// well inside registry rate limits.
pub fn assess_cached(client: &mut Client, reference: &str, local_digests: &[String]) -> Assessment {
    let key = (reference.to_string(), local_digests.to_vec());
    if let Some((at, a)) = CACHE.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
        if at.elapsed() < CACHE_TTL {
            return a.clone();
        }
    }
    let a = assess(client, reference, local_digests);
    if a.kind != "unknown" {
        CACHE.lock().unwrap_or_else(|p| p.into_inner()).insert(key, (std::time::Instant::now(), a.clone()));
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_references() {
        let r = parse_ref("postgres:16").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_str()), ("registry-1.docker.io", "library/postgres", "16"));
        let r = parse_ref("ghcr.io/open-webui/open-webui:v0.12.3").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_str()), ("ghcr.io", "open-webui/open-webui", "v0.12.3"));
        let r = parse_ref("docker.io/valkey/valkey:9@sha256:abc").unwrap();
        assert_eq!((r.repository.as_str(), r.tag.as_str(), r.digest.as_deref()), ("valkey/valkey", "9", Some("sha256:abc")));
        let r = parse_ref("localhost:5000/app").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_str()), ("localhost:5000", "app", "latest"));
    }

    #[test]
    fn finds_newer_tags() {
        let tags: Vec<String> =
            ["v0.12.3", "v0.12.4", "v0.13.4", "v0.13.4-cuda", "main", "v1.0.0-rc1", "0.14.0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(newer_tags("v0.12.3", &tags), NewerTags { same_series: Some("v0.13.4".into()), major: None });
        let pg: Vec<String> = ["15", "16", "17", "18", "16.4", "16-alpine", "18beta1"].iter().map(|s| s.to_string()).collect();
        assert_eq!(newer_tags("16", &pg), NewerTags { same_series: None, major: Some("18".into()) });
        let j: Vec<String> = ["3.7.6", "3.8.1", "3.10.0", "4.0.2"].iter().map(|s| s.to_string()).collect();
        assert_eq!(newer_tags("3.7.6", &j), NewerTags { same_series: Some("3.10.0".into()), major: Some("4.0.2".into()) });
        assert_eq!(newer_tags("alpine", &j), NewerTags::default());
        let immich: Vec<String> = ["14-vectorchord0.4.3-pgvectors0.2.0", "15-vectorchord0.4.3-pgvectors0.2.0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(newer_tags("14-vectorchord0.4.3-pgvectors0.2.0", &immich).major.as_deref(), Some("15-vectorchord0.4.3-pgvectors0.2.0"));
    }

    #[test]
    fn spots_databases() {
        assert!(is_database("library/postgres"));
        assert!(is_database("immich-app/postgres"));
        assert!(is_database("library/mariadb"));
        assert!(!is_database("valkey/valkey"));
        assert!(!is_database("joplin/server"));
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Contacts real registries. Run with `cargo test -p qk-intel -- --ignored`.
    #[test]
    #[ignore]
    fn live_registries() {
        let mut c = Client::new();
        for r in ["ghcr.io/open-webui/open-webui:v0.12.3", "postgres:16", "valkey/valkey:9", "joplin/server:3.7.6", "codeberg.org/forgejo/forgejo:17.0.1"] {
            let img = parse_ref(r).unwrap();
            let d = c.tag_digest(&img);
            println!("  assess: {:?}", assess(&mut c, r, &[]));
            let tags = c.tags(&img).map(|(t, _)| t);
            let n = tags.as_ref().map(|t| newer_tags(&img.tag, t));
            println!("{r}: digest={:?} tags={:?} newer={n:?}", d.map(|d| d[..19].to_string()), tags.as_ref().map(|t| t.len()));
        }
    }
}
