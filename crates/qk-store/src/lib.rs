//! Local SQLite storage. One database file per user, opened in WAL mode.

use std::path::Path;

use qk_core::host::{HostSpec, OsType};
use qk_core::updates::PackageUpdate;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use thiserror::Error;

const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001_init.sql"),
    include_str!("migrations/0002_scans.sql"),
];

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("host '{0}' already exists")]
    DuplicateHost(String),
    #[error("database schema version {0} is newer than this QuietKeep build supports")]
    SchemaTooNew(i64),
    #[error(transparent)]
    Invalid(#[from] qk_core::host::ValidationError),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Host {
    pub id: i64,
    #[serde(flatten)]
    pub spec: HostSpec,
    /// Pinned SHA-256 fingerprint of the host's SSH key, once the user has approved it.
    pub host_key: Option<String>,
    pub host_key_trusted: bool,
}

/// Patch state of one host from its most recent scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PatchStatus {
    pub host_id: i64,
    pub name: String,
    pub os_type: OsType,
    pub is_patch_target: bool,
    pub host_key_trusted: bool,
    pub last_scan_at: Option<i64>,
    pub pending: u32,
    pub security: u32,
    pub reboot_required: bool,
    pub scan_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Activity {
    pub at: i64,
    pub kind: String,
    pub message: String,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let mut store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let current: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let latest = MIGRATIONS.len() as i64;
        if current > latest {
            return Err(StoreError::SchemaTooNew(current));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", i as i64 + 1)?;
            tx.commit()?;
        }
        Ok(())
    }

    pub fn list_hosts(&self) -> Result<Vec<Host>> {
        let mut stmt = self.conn.prepare(&format!("SELECT {HOST_COLS} FROM hosts ORDER BY name"))?;
        let rows = stmt.query_map([], map_host)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn get_host(&self, id: i64) -> Result<Option<Host>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {HOST_COLS} FROM hosts WHERE id = ?1"), [id], map_host)
            .optional()?)
    }

    /// Pins the host's SSH key fingerprint after the user approved it.
    pub fn set_host_key(&mut self, id: i64, fingerprint: &str) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let name: Option<String> = tx
            .query_row("SELECT name FROM hosts WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        let Some(name) = name else { return Ok(false) };
        tx.execute(
            "UPDATE hosts SET host_key = ?1, updated_at = unixepoch() WHERE id = ?2",
            params![fingerprint, id],
        )?;
        log(&tx, "host.key_trusted", Some(id), &format!("Trusted host key for {name}: {fingerprint}"))?;
        tx.commit()?;
        Ok(true)
    }

/// Replaces the host's pending updates with the results of a successful scan.
    pub fn record_scan(&mut self, id: i64, updates: &[PackageUpdate], reboot_required: bool) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM pending_updates WHERE host_id = ?1", [id])?;
        {
            let mut ins = tx.prepare(
                "INSERT OR REPLACE INTO pending_updates
                 (host_id, name, current_version, available_version, source, security)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for u in updates {
                ins.execute(params![id, u.name, u.current_version, u.available_version, u.source, u.security])?;
            }
        }
        tx.execute(
            "UPDATE hosts SET last_scan_at = unixepoch(), reboot_required = ?1, scan_error = NULL WHERE id = ?2",
            params![reboot_required, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Records a failed scan without discarding the last known pending updates.
    pub fn record_scan_error(&mut self, id: i64, message: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE hosts SET last_scan_at = unixepoch(), scan_error = ?1 WHERE id = ?2",
            params![message, id],
        )?;
        Ok(())
    }

    pub fn pending_updates(&self, id: i64) -> Result<Vec<PackageUpdate>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, current_version, available_version, source, security
             FROM pending_updates WHERE host_id = ?1 ORDER BY security DESC, name",
        )?;
        let rows = stmt.query_map([id], |r| {
            Ok(PackageUpdate {
                name: r.get(0)?,
                current_version: r.get(1)?,
                available_version: r.get(2)?,
                source: r.get(3)?,
                security: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn patch_status(&self) -> Result<Vec<PatchStatus>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.id, h.name, h.os_type, h.is_patch_target, h.host_key IS NOT NULL, h.last_scan_at,
                    COUNT(u.name), COALESCE(SUM(u.security), 0), h.reboot_required, h.scan_error
             FROM hosts h LEFT JOIN pending_updates u ON u.host_id = h.id
             GROUP BY h.id ORDER BY h.name",
        )?;
        let rows = stmt.query_map([], |r| {
            let os: String = r.get(2)?;
            Ok(PatchStatus {
                host_id: r.get(0)?,
                name: r.get(1)?,
                os_type: os.parse::<OsType>().map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
                })?,
                is_patch_target: r.get(3)?,
                host_key_trusted: r.get(4)?,
                last_scan_at: r.get(5)?,
                pending: r.get(6)?,
                security: r.get(7)?,
                reboot_required: r.get(8)?,
                scan_error: r.get(9)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn log_activity(&self, kind: &str, host_id: Option<i64>, message: &str) -> Result<()> {
        log(&self.conn, kind, host_id, message)
    }

    pub fn host_names(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT name FROM hosts")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn add_host(&mut self, spec: &HostSpec) -> Result<i64> {
        let tx = self.conn.transaction()?;
        let id = insert_host(&tx, spec)?;
        log(&tx, "host.added", Some(id), &format!("Added host {}", spec.name))?;
        tx.commit()?;
        Ok(id)
    }

    /// Inserts all hosts in one transaction; if any insert fails nothing is stored.
    pub fn add_hosts(&mut self, specs: &[HostSpec]) -> Result<usize> {
        let tx = self.conn.transaction()?;
        for spec in specs {
            insert_host(&tx, spec)?;
        }
        log(&tx, "host.imported", None, &format!("Imported {} hosts from CSV", specs.len()))?;
        tx.commit()?;
        Ok(specs.len())
    }

    pub fn delete_host(&mut self, id: i64) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let name: Option<String> = tx
            .query_row("SELECT name FROM hosts WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        let Some(name) = name else { return Ok(false) };
        tx.execute("DELETE FROM hosts WHERE id = ?1", [id])?;
        log(&tx, "host.deleted", None, &format!("Removed host {name}"))?;
        tx.commit()?;
        Ok(true)
    }

    pub fn recent_activity(&self, limit: u32) -> Result<Vec<Activity>> {
        let mut stmt = self
            .conn
            .prepare("SELECT at, kind, message FROM activity_log ORDER BY at DESC, id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit], |r| {
            Ok(Activity { at: r.get(0)?, kind: r.get(1)?, message: r.get(2)? })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}

const HOST_COLS: &str = "id, name, address, username, os_type, is_patch_target, has_docker, host_key";

fn map_host(r: &rusqlite::Row<'_>) -> rusqlite::Result<Host> {
    let os: String = r.get(4)?;
    let host_key: Option<String> = r.get(7)?;
    Ok(Host {
        id: r.get(0)?,
        spec: HostSpec {
            name: r.get(1)?,
            address: r.get(2)?,
            username: r.get(3)?,
            os_type: os.parse::<OsType>().map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
            })?,
            is_patch_target: r.get(5)?,
            has_docker: r.get(6)?,
        },
        host_key_trusted: host_key.is_some(),
        host_key,
    })
}

fn insert_host(conn: &Connection, spec: &HostSpec) -> Result<i64> {
    spec.validate()?;
    let res = conn.execute(
        "INSERT INTO hosts (name, address, username, os_type, is_patch_target, has_docker)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            spec.name,
            spec.address,
            spec.username,
            spec.os_type.as_str(),
            spec.is_patch_target,
            spec.has_docker
        ],
    );
    match res {
        Ok(_) => Ok(conn.last_insert_rowid()),
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
            Err(StoreError::DuplicateHost(spec.name.clone()))
        }
        Err(e) => Err(e.into()),
    }
}

fn log(conn: &Connection, kind: &str, host_id: Option<i64>, message: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO activity_log (kind, host_id, message) VALUES (?1, ?2, ?3)",
        params![kind, host_id, message],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str) -> HostSpec {
        HostSpec {
            name: name.into(),
            address: "192.0.2.10".into(),
            username: "admin".into(),
            os_type: OsType::Apt,
            is_patch_target: true,
            has_docker: false,
        }
    }

    #[test]
    fn add_list_delete() {
        let mut s = Store::open_in_memory().unwrap();
        let id = s.add_host(&spec("web-01")).unwrap();
        s.add_host(&spec("db-01")).unwrap();
        let hosts = s.list_hosts().unwrap();
        assert_eq!(hosts.iter().map(|h| h.spec.name.as_str()).collect::<Vec<_>>(), ["db-01", "web-01"]);
        assert!(!hosts[0].host_key_trusted);
        assert!(matches!(s.add_host(&spec("WEB-01")), Err(StoreError::DuplicateHost(_))));
        assert!(s.delete_host(id).unwrap());
        assert!(!s.delete_host(id).unwrap());
        assert_eq!(s.list_hosts().unwrap().len(), 1);
        assert_eq!(s.recent_activity(10).unwrap()[0].kind, "host.deleted");
    }

    #[test]
    fn bulk_insert_is_atomic() {
        let mut s = Store::open_in_memory().unwrap();
        s.add_host(&spec("b")).unwrap();
        assert!(s.add_hosts(&[spec("a"), spec("b")]).is_err());
        assert_eq!(s.list_hosts().unwrap().len(), 1);
        assert_eq!(s.add_hosts(&[spec("a"), spec("c")]).unwrap(), 2);
    }

    #[test]
    fn rejects_invalid_spec() {
        let mut s = Store::open_in_memory().unwrap();
        let mut bad = spec("x");
        bad.username = "root;id".into();
        assert!(matches!(s.add_host(&bad), Err(StoreError::Invalid(_))));
    }

    #[test]
    fn reopen_keeps_schema() {
        let dir = std::env::temp_dir().join(format!("qk-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        Store::open(&path).unwrap().add_host(&spec("a")).unwrap();
        assert_eq!(Store::open(&path).unwrap().list_hosts().unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pins_host_key() {
        let mut store = Store::open_in_memory().unwrap();
        let spec = HostSpec {
            name: "web".into(),
            address: "198.51.100.5".into(),
            username: "admin".into(),
            os_type: OsType::Apt,
            is_patch_target: true,
            has_docker: false,
        };
        let id = store.add_host(&spec).unwrap();
        assert!(!store.get_host(id).unwrap().unwrap().host_key_trusted);
        assert!(store.set_host_key(id, "SHA256:abc").unwrap());
        let h = store.get_host(id).unwrap().unwrap();
        assert!(h.host_key_trusted);
        assert_eq!(h.host_key.as_deref(), Some("SHA256:abc"));
        assert!(!store.set_host_key(999, "SHA256:abc").unwrap());
        assert_eq!(store.recent_activity(1).unwrap()[0].kind, "host.key_trusted");
    }

    #[test]
    fn records_scans() {
        let mut store = Store::open_in_memory().unwrap();
        let spec = HostSpec {
            name: "db".into(),
            address: "198.51.100.6".into(),
            username: "admin".into(),
            os_type: OsType::Apt,
            is_patch_target: true,
            has_docker: false,
        };
        let id = store.add_host(&spec).unwrap();
        let up = |n: &str, sec| PackageUpdate {
            name: n.into(),
            current_version: Some("1".into()),
            available_version: "2".into(),
            source: Some("noble".into()),
            security: sec,
        };
        store.record_scan(id, &[up("curl", false), up("openssl", true)], true).unwrap();
        let s = &store.patch_status().unwrap()[0];
        assert_eq!((s.pending, s.security, s.reboot_required), (2, 1, true));
        assert!(s.last_scan_at.is_some() && s.scan_error.is_none());
        assert_eq!(store.pending_updates(id).unwrap()[0].name, "openssl");

        store.record_scan_error(id, "timeout").unwrap();
        let s = &store.patch_status().unwrap()[0];
        assert_eq!(s.pending, 2);
        assert_eq!(s.scan_error.as_deref(), Some("timeout"));

        store.record_scan(id, &[], false).unwrap();
        let s = &store.patch_status().unwrap()[0];
        assert_eq!((s.pending, s.reboot_required), (0, false));
        assert!(s.scan_error.is_none());

        store.delete_host(id).unwrap();
        assert!(store.patch_status().unwrap().is_empty());
    }

    #[test]
    fn settings_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.get_setting("scan.interval_minutes").unwrap(), None);
        store.set_setting("scan.interval_minutes", "60").unwrap();
        store.set_setting("scan.interval_minutes", "360").unwrap();
        assert_eq!(store.get_setting("scan.interval_minutes").unwrap().as_deref(), Some("360"));
    }
}
