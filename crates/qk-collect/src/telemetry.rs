//! Read-only system telemetry: load, memory, root disk, uptime, kernel and OS name.

use qk_ssh::{Command, Connection, Result};
use serde::Serialize;

const SCRIPT: &str = r#"echo "load=$(cut -d' ' -f1 /proc/loadavg)"
echo "cpus=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN)"
echo "uptime=$(cut -d' ' -f1 /proc/uptime)"
awk '/^MemTotal:/{print "mem_total="$2} /^MemAvailable:/{print "mem_avail="$2}' /proc/meminfo
df -P / | awk 'NR==2{sub(/%/,"",$5); print "disk_used="$5}'
echo "kernel=$(uname -r)"
(. /etc/os-release 2>/dev/null; echo "os=$PRETTY_NAME")"#;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Telemetry {
    pub load1: f64,
    pub cpus: u32,
    pub mem_used_pct: f64,
    pub disk_used_pct: f64,
    pub uptime_s: i64,
    pub kernel: String,
    pub os_name: String,
}

pub fn parse(output: &str) -> Option<Telemetry> {
    let mut t = Telemetry::default();
    let (mut total, mut avail) = (0f64, 0f64);
    let mut seen = 0;
    for line in output.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim();
        match k.trim() {
            "load" => t.load1 = v.parse().ok()?,
            "cpus" => t.cpus = v.parse().unwrap_or(1),
            "uptime" => t.uptime_s = v.parse::<f64>().ok()? as i64,
            "mem_total" => total = v.parse().ok()?,
            "mem_avail" => avail = v.parse().ok()?,
            "disk_used" => t.disk_used_pct = v.parse().ok()?,
            "kernel" => t.kernel = v.to_string(),
            "os" => t.os_name = v.to_string(),
            _ => continue,
        }
        seen += 1;
    }
    if seen < 5 || total <= 0.0 {
        return None;
    }
    t.mem_used_pct = ((total - avail) / total * 1000.0).round() / 10.0;
    Some(t)
}

pub async fn collect(conn: &Connection) -> Result<Option<Telemetry>> {
    let out = conn.run(&Command::new("sh").args(["-c", SCRIPT])).await?;
    Ok(parse(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let out = "load=1.26\ncpus=8\nuptime=4994.11\nmem_total=32000000\nmem_avail=24000000\ndisk_used=24\nkernel=6.8.0-1060-aws\nos=Ubuntu 22.04.5 LTS\n";
        let t = parse(out).unwrap();
        assert_eq!(t.load1, 1.26);
        assert_eq!(t.cpus, 8);
        assert_eq!(t.uptime_s, 4994);
        assert_eq!(t.mem_used_pct, 25.0);
        assert_eq!(t.disk_used_pct, 24.0);
        assert_eq!(t.os_name, "Ubuntu 22.04.5 LTS");
        assert!(parse("garbage").is_none());
    }
}
