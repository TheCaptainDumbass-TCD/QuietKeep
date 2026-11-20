//! Host list import and export. The column layout matches the original QuietKeep
//! export so existing lists import unchanged:
//! `hostname,ip_address,username,os_type,is_patch_target,has_docker`.

use std::collections::HashSet;
use std::io::{Read, Write};

use thiserror::Error;

use crate::host::{HostSpec, OsType};

pub const HEADERS: [&str; 6] = [
    "hostname",
    "ip_address",
    "username",
    "os_type",
    "is_patch_target",
    "has_docker",
];
const REQUIRED: [&str; 4] = ["hostname", "ip_address", "username", "os_type"];

#[derive(Debug, Error)]
pub enum CsvError {
    #[error("CSV is missing required columns: {0}")]
    MissingColumns(String),
    #[error(transparent)]
    Csv(#[from] csv::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowError {
    /// 1-based line number in the file, counting the header as line 1.
    pub line: u64,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub hosts: Vec<HostSpec>,
    /// Names already present (either in `existing` or earlier in the same file).
    pub duplicates: Vec<String>,
    pub errors: Vec<RowError>,
}

fn parse_bool(raw: Option<&str>, default: bool) -> Result<bool, String> {
    match raw.map(|s| s.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(s) if s.is_empty() => Ok(default),
        Some(s) => match s.as_str() {
            "true" | "1" | "yes" | "y" => Ok(true),
            "false" | "0" | "no" | "n" => Ok(false),
            _ => Err(format!("invalid boolean '{s}'")),
        },
    }
}

/// Parses and validates a host CSV. Rows with errors are reported, not imported.
/// `existing` holds host names already stored, compared case-insensitively.
pub fn import<R: Read>(reader: R, existing: &HashSet<String>) -> Result<ImportReport, CsvError> {
    let mut rdr = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(true)
        .from_reader(reader);

    let headers: Vec<String> = rdr
        .headers()?
        .iter()
        .map(|h| h.trim_start_matches('\u{feff}').trim().to_ascii_lowercase())
        .collect();
    let missing: Vec<&str> = REQUIRED
        .iter()
        .copied()
        .filter(|r| !headers.iter().any(|h| h == r))
        .collect();
    if !missing.is_empty() {
        return Err(CsvError::MissingColumns(missing.join(", ")));
    }
    let col = |name: &str| headers.iter().position(|h| h == name);
    let idx: Vec<Option<usize>> = HEADERS.iter().map(|h| col(h)).collect();

    let mut seen: HashSet<String> = existing.iter().map(|n| n.to_ascii_lowercase()).collect();
    let mut report = ImportReport::default();

    for (i, record) in rdr.records().enumerate() {
        let line = i as u64 + 2;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                report.errors.push(RowError { line, message: e.to_string() });
                continue;
            }
        };
        if record.iter().all(|f| f.is_empty()) {
            continue;
        }
        let field = |n: usize| idx[n].and_then(|c| record.get(c));
        let text = |n: usize| field(n).unwrap_or("").to_string();

        let parsed = (|| -> Result<HostSpec, String> {
            let (name, address, username, os) = (text(0), text(1), text(2), text(3));
            if name.is_empty() || address.is_empty() || username.is_empty() || os.is_empty() {
                return Err("missing required fields".into());
            }
            let spec = HostSpec {
                os_type: os.parse::<OsType>().map_err(|e| e.to_string())?,
                is_patch_target: parse_bool(field(4), true)?,
                has_docker: parse_bool(field(5), false)?,
                name,
                address,
                username,
            };
            spec.validate().map_err(|e| e.to_string())?;
            Ok(spec)
        })();

        match parsed {
            Ok(spec) => {
                if seen.insert(spec.name.to_ascii_lowercase()) {
                    report.hosts.push(spec);
                } else {
                    report.duplicates.push(spec.name);
                }
            }
            Err(message) => report.errors.push(RowError { line, message }),
        }
    }
    Ok(report)
}

pub fn export<'a, W, I>(writer: W, hosts: I) -> Result<(), csv::Error>
where
    W: Write,
    I: IntoIterator<Item = &'a HostSpec>,
{
    let mut wtr = csv::Writer::from_writer(writer);
    wtr.write_record(HEADERS)?;
    for h in hosts {
        wtr.write_record([
            h.name.as_str(),
            h.address.as_str(),
            h.username.as_str(),
            h.os_type.as_str(),
            if h.is_patch_target { "true" } else { "false" },
            if h.has_docker { "true" } else { "false" },
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: &str = "\u{feff}hostname,ip_address,username,os_type,is_patch_target,has_docker\n\
web-server-01,192.0.2.10,admin,apt,True,False\n\
db-server-01,192.0.2.11,admin,apt,true,true\n\
proxmox-node-1,192.0.2.20,root,proxmox,true,false\n\
arch-desktop,192.0.2.30,user,pacman,,\n\
bad-user,192.0.2.40,bob;id,apt,true,false\n\
bad-os,192.0.2.41,admin,yum,true,false\n\
WEB-SERVER-01,192.0.2.12,admin,apt,true,false\n";

    #[test]
    fn imports_legacy_export() {
        let report = import(LEGACY.as_bytes(), &HashSet::new()).unwrap();
        let names: Vec<_> = report.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["web-server-01", "db-server-01", "proxmox-node-1", "arch-desktop"]);
        assert!(report.hosts[0].is_patch_target && !report.hosts[0].has_docker);
        assert!(report.hosts[1].has_docker);
        assert!(report.hosts[3].is_patch_target && !report.hosts[3].has_docker);
        assert_eq!(report.duplicates, ["WEB-SERVER-01"]);
        let lines: Vec<_> = report.errors.iter().map(|e| e.line).collect();
        assert_eq!(lines, [6, 7]);
    }

    #[test]
    fn skips_existing_and_rejects_missing_columns() {
        let existing = HashSet::from(["DB-SERVER-01".to_string()]);
        let report = import(LEGACY.as_bytes(), &existing).unwrap();
        assert!(report.duplicates.contains(&"db-server-01".to_string()));
        assert!(matches!(
            import("hostname,username\nx,y\n".as_bytes(), &HashSet::new()),
            Err(CsvError::MissingColumns(_))
        ));
    }

    #[test]
    fn round_trip() {
        let report = import(LEGACY.as_bytes(), &HashSet::new()).unwrap();
        let mut out = Vec::new();
        export(&mut out, &report.hosts).unwrap();
        let again = import(out.as_slice(), &HashSet::new()).unwrap();
        assert_eq!(again.hosts, report.hosts);
        assert!(again.errors.is_empty());
    }
}
