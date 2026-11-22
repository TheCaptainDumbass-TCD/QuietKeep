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
    include_str!("migrations/0003_docker.sql"),
    include_str!("migrations/0004_metrics.sql"),
    include_str!("migrations/0005_access.sql"),
    include_str!("migrations/0006_held.sql"),
    include_str!("migrations/0007_update_note.sql"),
    include_str!("migrations/0008_releases.sql"),
    include_str!("migrations/0009_pins.sql"),
    include_str!("migrations/0010_finished.sql"),
    include_str!("migrations/0011_snooze.sql"),
    include_str!("migrations/0012_packages.sql"),
    include_str!("migrations/0013_sources.sql"),
    include_str!("migrations/0014_autoremove.sql"),
    include_str!("migrations/0015_kernel_notes.sql"),
];

/// What a Proxmox host's kernel changelog says about its running kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelNotes {
    pub host_id: i64,
    pub running: String,
    pub ubuntu_base: Option<String>,
    pub fixed_cves: Vec<String>,
}

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
    /// QuietKeep's own key logged in to this host the last time it tried.
    pub access_ok: bool,
    /// Release name reported by the host, such as "Debian GNU/Linux 13 (trixie)".
    pub os_name: Option<String>,
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
    /// Updates apt upgrade skips (phased or kept back); not counted in `pending`.
    pub held: u32,
    pub os_name: Option<String>,
    /// Held updates apt keeps back because they need new packages, such as new kernels.
    pub kept_back: u32,
    /// Packages `apt-get autoremove` would remove.
    pub autoremove: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ContainerRow {
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub project: Option<String>,
    pub service: Option<String>,
    pub config_file: Option<String>,
    pub update_available: Option<bool>,
    pub update_note: Option<String>,
    pub update_kind: Option<String>,
    pub latest_tag: Option<String>,
    pub major_tag: Option<String>,
    pub configured_image: Option<String>,
    pub latest_digest: Option<String>,
    pub finished_at: Option<i64>,
    /// Whole days since a stopped container stopped. Computed when read, never stored.
    pub stopped_days: Option<i64>,
    /// The user hid the notice for this major release.
    pub snoozed: bool,
}

/// One installed package on a saved host, with the host's OS release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPackage {
    pub host_id: i64,
    pub host: String,
    pub os_id: Option<String>,
    pub os_version: Option<String>,
    pub package: qk_core::updates::InstalledPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerHost {
    pub host_id: i64,
    pub name: String,
    pub host_key_trusted: bool,
    pub docker_scan_at: Option<i64>,
    pub docker_error: Option<String>,
    pub containers: Vec<ContainerRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct MetricSample {
    pub at: i64,
    pub load1: f64,
    pub cpus: u32,
    pub mem_used_pct: f64,
    pub disk_used_pct: f64,
    pub uptime_s: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostMetrics {
    pub host_id: i64,
    pub name: String,
    pub kernel: Option<String>,
    pub os_name: Option<String>,
    pub samples: Vec<MetricSample>,
}

/// Samples older than this are pruned when new ones arrive.
pub const METRICS_RETENTION_SECS: i64 = 7 * 24 * 3600;

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
    pub fn set_access_ok(&mut self, id: i64, ok: bool) -> Result<()> {
        self.conn.execute("UPDATE hosts SET access_ok = ?2 WHERE id = ?1", rusqlite::params![id, ok])?;
        Ok(())
    }

    pub fn set_host_key(&mut self, id: i64, fingerprint: &str) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let name: Option<String> = tx
            .query_row("SELECT name FROM hosts WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        let Some(name) = name else { return Ok(false) };
        tx.execute(
            "UPDATE hosts SET host_key = ?1, access_ok = CASE WHEN host_key IS ?1 THEN access_ok ELSE 0 END, updated_at = unixepoch() WHERE id = ?2",
            params![fingerprint, id],
        )?;
        log(&tx, "host.key_trusted", Some(id), &format!("Trusted host key for {name}: {fingerprint}"))?;
        tx.commit()?;
        Ok(true)
    }

/// Replaces the host's pending updates with the results of a successful scan.
    pub fn record_scan(&mut self, id: i64, updates: &[PackageUpdate], reboot_required: bool, autoremove: u32) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM pending_updates WHERE host_id = ?1", [id])?;
        {
            let mut ins = tx.prepare(
                "INSERT OR REPLACE INTO pending_updates
                 (host_id, name, current_version, available_version, source, security, held)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for u in updates {
                ins.execute(params![id, u.name, u.current_version, u.available_version, u.source, u.security, u.held])?;
            }
        }
        tx.execute(
            "UPDATE hosts SET last_scan_at = unixepoch(), reboot_required = ?1, autoremove = ?2, scan_error = NULL WHERE id = ?3",
            params![reboot_required, autoremove, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Records a failed scan without discarding the last known pending updates.
    /// Replaces the installed package list for a host. An empty list keeps the old one,
    /// so a failed inventory never clears known packages.
    pub fn record_packages(&mut self, id: i64, packages: &[qk_core::updates::InstalledPackage]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM host_packages WHERE host_id = ?1", [id])?;
        {
            let mut ins = tx.prepare(
                "INSERT OR REPLACE INTO host_packages (host_id, name, version, source_name, source_version) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for p in packages {
                ins.execute(rusqlite::params![id, p.name, p.version, p.source, p.source_version])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Packages with a pending update on each host, as (host id, package).
    pub fn pending_packages(&self) -> Result<Vec<(i64, String)>> {
        let mut stmt = self.conn.prepare("SELECT host_id, name FROM pending_updates")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn record_os_release(&mut self, id: i64, os_id: &str, os_version: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE hosts SET os_id = ?2, os_version = ?3 WHERE id = ?1",
            rusqlite::params![id, os_id, os_version],
        )?;
        Ok(())
    }

    /// Records what a Proxmox kernel changelog says about the running kernel.
    pub fn record_kernel_notes(&mut self, id: i64, running: &str, ubuntu_base: Option<&str>, fixed_cves: &[String]) -> Result<()> {
        self.conn.execute(
            "UPDATE hosts SET kernel_running = ?2, kernel_base = ?3, kernel_cves = ?4 WHERE id = ?1",
            rusqlite::params![id, running, ubuntu_base, fixed_cves.join(" ")],
        )?;
        Ok(())
    }

    /// Kernel notes of every host that has them.
    pub fn kernel_notes(&self) -> Result<Vec<KernelNotes>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kernel_running, kernel_base, COALESCE(kernel_cves, '') FROM hosts WHERE kernel_running IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            let cves: String = r.get(3)?;
            Ok(KernelNotes {
                host_id: r.get(0)?,
                running: r.get(1)?,
                ubuntu_base: r.get(2)?,
                fixed_cves: cves.split_whitespace().map(str::to_string).collect(),
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Installed packages of every saved host.
    pub fn all_packages(&self) -> Result<Vec<HostPackage>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.id, h.name, h.os_id, h.os_version, p.name, p.version, COALESCE(p.source_name, p.name), COALESCE(p.source_version, p.version)
             FROM host_packages p JOIN hosts h ON h.id = p.host_id ORDER BY h.name, p.name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(HostPackage {
                host_id: r.get(0)?,
                host: r.get(1)?,
                os_id: r.get(2)?,
                os_version: r.get(3)?,
                package: qk_core::updates::InstalledPackage {
                    name: r.get(4)?,
                    version: r.get(5)?,
                    source: r.get(6)?,
                    source_version: r.get(7)?,
                },
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn record_scan_error(&mut self, id: i64, message: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE hosts SET last_scan_at = unixepoch(), scan_error = ?1 WHERE id = ?2",
            params![message, id],
        )?;
        Ok(())
    }

    pub fn pending_updates(&self, id: i64) -> Result<Vec<PackageUpdate>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, current_version, available_version, source, security, held
             FROM pending_updates WHERE host_id = ?1 ORDER BY held IS NOT NULL, security DESC, name",
        )?;
        let rows = stmt.query_map([id], |r| {
            Ok(PackageUpdate {
                name: r.get(0)?,
                current_version: r.get(1)?,
                available_version: r.get(2)?,
                source: r.get(3)?,
                security: r.get(4)?,
                held: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn patch_status(&self) -> Result<Vec<PatchStatus>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.id, h.name, h.os_type, h.is_patch_target, h.host_key IS NOT NULL, h.last_scan_at,
                    COUNT(u.name) - COUNT(u.held), COALESCE(SUM(u.security AND u.held IS NULL), 0), h.reboot_required, h.scan_error,
                    COUNT(u.held), h.os_name, COALESCE(SUM(u.held = 'kept back'), 0), h.autoremove
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
                held: r.get(10)?,
                os_name: r.get(11)?,
                kept_back: r.get(12)?,
                autoremove: r.get(13)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
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

pub fn record_docker(&mut self, id: i64, containers: &[ContainerRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM containers WHERE host_id = ?1", [id])?;
        {
            let mut ins = tx.prepare(
                "INSERT OR REPLACE INTO containers
                 (host_id, name, image, state, status, project, service, config_file, update_available, update_note,
                  update_kind, latest_tag, major_tag, configured_image, latest_digest, finished_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            )?;
            for c in containers {
                ins.execute(params![
                    id, c.name, c.image, c.state, c.status, c.project, c.service, c.config_file, c.update_available,
                    c.update_note, c.update_kind, c.latest_tag, c.major_tag, c.configured_image, c.latest_digest, c.finished_at
                ])?;
            }
        }
        tx.execute(
            "UPDATE hosts SET docker_scan_at = unixepoch(), docker_error = NULL WHERE id = ?1",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_docker_error(&mut self, id: i64, message: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE hosts SET docker_scan_at = unixepoch(), docker_error = ?1 WHERE id = ?2",
            params![message, id],
        )?;
        Ok(())
    }

    /// Hosts marked as Docker hosts with their containers from the last scan.
    pub fn docker_status(&self) -> Result<Vec<DockerHost>> {
        let mut hosts_stmt = self.conn.prepare(
            "SELECT id, name, host_key IS NOT NULL, docker_scan_at, docker_error
             FROM hosts WHERE has_docker = 1 ORDER BY name",
        )?;
        let mut hosts: Vec<DockerHost> = hosts_stmt
            .query_map([], |r| {
                Ok(DockerHost {
                    host_id: r.get(0)?,
                    name: r.get(1)?,
                    host_key_trusted: r.get(2)?,
                    docker_scan_at: r.get(3)?,
                    docker_error: r.get(4)?,
                    containers: Vec::new(),
                })
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut c_stmt = self.conn.prepare(
            "SELECT name, image, state, status, project, service, config_file, update_available, update_note, update_kind, latest_tag, major_tag,
                    configured_image, latest_digest, finished_at,
                    CASE WHEN finished_at IS NULL THEN NULL ELSE (unixepoch() - finished_at) / 86400 END,
                    EXISTS(SELECT 1 FROM docker_snoozes s WHERE s.host_id = containers.host_id
                           AND s.container = containers.name AND s.major_tag = containers.major_tag)
             FROM containers WHERE host_id = ?1 ORDER BY project IS NULL, project, name",
        )?;
        for h in &mut hosts {
            h.containers = c_stmt
                .query_map([h.host_id], |r| {
                    Ok(ContainerRow {
                        name: r.get(0)?,
                        image: r.get(1)?,
                        state: r.get(2)?,
                        status: r.get(3)?,
                        project: r.get(4)?,
                        service: r.get(5)?,
                        config_file: r.get(6)?,
                        update_available: r.get(7)?,
                        update_note: r.get(8)?,
                        update_kind: r.get(9)?,
                        latest_tag: r.get(10)?,
                        major_tag: r.get(11)?,
                        configured_image: r.get(12)?,
                        latest_digest: r.get(13)?,
                        finished_at: r.get(14)?,
                        stopped_days: r.get(15)?,
                        snoozed: r.get(16)?,
                    })
                })?
                .collect::<std::result::Result<_, _>>()?;
        }
        Ok(hosts)
    }

pub fn record_metrics(&mut self, id: i64, m: &MetricSample, kernel: &str, os_name: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO metrics (host_id, at, load1, cpus, mem_used_pct, disk_used_pct, uptime_s)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, m.at, m.load1, m.cpus, m.mem_used_pct, m.disk_used_pct, m.uptime_s],
        )?;
        tx.execute(
            "DELETE FROM metrics WHERE host_id = ?1 AND at < ?2",
            params![id, m.at - METRICS_RETENTION_SECS],
        )?;
        tx.execute(
            "UPDATE hosts SET kernel = ?1, os_name = ?2 WHERE id = ?3",
            params![kernel, os_name, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Hosts with at least one sample since `since`, oldest sample first.
    pub fn metrics_since(&self, since: i64) -> Result<Vec<HostMetrics>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.id, h.name, h.kernel, h.os_name, m.at, m.load1, m.cpus, m.mem_used_pct, m.disk_used_pct, m.uptime_s
             FROM metrics m JOIN hosts h ON h.id = m.host_id
             WHERE m.at >= ?1 ORDER BY h.name, m.at",
        )?;
        let mut out: Vec<HostMetrics> = Vec::new();
        let rows = stmt.query_map([since], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                MetricSample {
                    at: r.get(4)?,
                    load1: r.get(5)?,
                    cpus: r.get(6)?,
                    mem_used_pct: r.get(7)?,
                    disk_used_pct: r.get(8)?,
                    uptime_s: r.get(9)?,
                },
            ))
        })?;
        for row in rows {
            let (id, name, kernel, os_name, sample) = row?;
            match out.last_mut() {
                Some(h) if h.host_id == id => h.samples.push(sample),
                _ => out.push(HostMetrics { host_id: id, name, kernel, os_name, samples: vec![sample] }),
            }
        }
        Ok(out)
    }

    /// Hides the major release notice for one container until a newer major release appears.
    /// `None` shows the notice again.
    pub fn set_major_snooze(&mut self, host_id: i64, container: &str, major_tag: Option<&str>) -> Result<()> {
        match major_tag {
            Some(tag) => self.conn.execute(
                "INSERT INTO docker_snoozes (host_id, container, major_tag) VALUES (?1, ?2, ?3)
                 ON CONFLICT (host_id, container) DO UPDATE SET major_tag = excluded.major_tag",
                rusqlite::params![host_id, container, tag],
            )?,
            None => self.conn.execute(
                "DELETE FROM docker_snoozes WHERE host_id = ?1 AND container = ?2",
                rusqlite::params![host_id, container],
            )?,
        };
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

const HOST_COLS: &str = "id, name, address, username, os_type, is_patch_target, has_docker, host_key, access_ok, os_name";

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
        access_ok: r.get(8)?,
        os_name: r.get(9)?,
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
            held: None,
        };
        store.record_scan(id, &[up("curl", false), up("openssl", true)], true, 3).unwrap();
        let s = &store.patch_status().unwrap()[0];
        assert_eq!((s.pending, s.security, s.reboot_required), (2, 1, true));
        assert!(s.last_scan_at.is_some() && s.scan_error.is_none());
        assert_eq!(store.pending_updates(id).unwrap()[0].name, "openssl");

        store.record_scan_error(id, "timeout").unwrap();
        let s = &store.patch_status().unwrap()[0];
        assert_eq!(s.pending, 2);
        assert_eq!(s.scan_error.as_deref(), Some("timeout"));

        store.record_scan(id, &[], false, 0).unwrap();
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

    #[test]
    fn records_docker() {
        let mut store = Store::open_in_memory().unwrap();
        let spec = HostSpec {
            name: "dock".into(),
            address: "198.51.100.7".into(),
            username: "admin".into(),
            os_type: OsType::Apt,
            is_patch_target: true,
            has_docker: true,
        };
        let id = store.add_host(&spec).unwrap();
        let c = ContainerRow {
            name: "web-web-1".into(),
            image: "nginx:alpine".into(),
            state: "running".into(),
            status: "Up".into(),
            project: Some("web".into()),
            service: Some("web".into()),
            config_file: Some("/srv/web/compose.yaml".into()),
            update_available: Some(true),
            update_note: None,
            update_kind: Some("release".into()),
            latest_tag: Some("1.27.0".into()),
            major_tag: None,
            configured_image: Some("nginx:alpine".into()),
            latest_digest: None,
            finished_at: None,
            stopped_days: None,
            snoozed: false,
        };
        store.record_docker(id, &[c.clone()]).unwrap();
        let d = &store.docker_status().unwrap()[0];
        assert_eq!(d.containers, vec![c]);
        assert!(d.docker_scan_at.is_some());
        store.record_docker_error(id, "docker not found").unwrap();
        assert_eq!(store.docker_status().unwrap()[0].docker_error.as_deref(), Some("docker not found"));
    }

    #[test]
    fn records_and_prunes_metrics() {
        let mut store = Store::open_in_memory().unwrap();
        let spec = HostSpec {
            name: "m1".into(),
            address: "198.51.100.8".into(),
            username: "admin".into(),
            os_type: OsType::Apt,
            is_patch_target: true,
            has_docker: false,
        };
        let id = store.add_host(&spec).unwrap();
        let sample = |at| MetricSample { at, load1: 0.5, cpus: 4, mem_used_pct: 40.0, disk_used_pct: 60.0, uptime_s: 100 };
        store.record_metrics(id, &sample(1_000), "6.1", "Debian").unwrap();
        store.record_metrics(id, &sample(2_000), "6.1", "Debian").unwrap();
        store.record_metrics(id, &sample(1_000 + METRICS_RETENTION_SECS + 1), "6.2", "Debian").unwrap();
        let m = store.metrics_since(0).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].samples.len(), 2);
        assert_eq!(m[0].kernel.as_deref(), Some("6.2"));
    }
}
