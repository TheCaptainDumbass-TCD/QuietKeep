//! Scans a local Debian/Ubuntu sshd when QK_SSH_TEST_PORT, QK_SSH_TEST_KEY and
//! QK_SSH_TEST_FINGERPRINT are set; otherwise the test is skipped.

use std::sync::Arc;
use std::time::Duration;

use qk_core::host::OsType;
use qk_ssh::{connect, Target, TrustPolicy};

#[tokio::test]
async fn scans_apt_host() {
    let (Ok(port), Ok(key), Ok(fp)) = (
        std::env::var("QK_SSH_TEST_PORT"),
        std::env::var("QK_SSH_TEST_KEY"),
        std::env::var("QK_SSH_TEST_FINGERPRINT"),
    ) else {
        eprintln!("skipped: local sshd not configured");
        return;
    };
    let identity = qk_ssh::load_or_create_identity(std::path::Path::new(&key), None)
        .unwrap()
        .key;
    let target = Target {
        address: "127.0.0.1".into(),
        port: port.parse().unwrap(),
        username: std::env::var("USER").unwrap(),
    };
    let conn = connect(
        &target,
        Arc::new(identity),
        TrustPolicy::Pinned(fp),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let result = qk_collect::scan(&conn, OsType::Apt).await.unwrap();
    eprintln!(
        "updates={} security={} reboot_required={}",
        result.updates.len(),
        result.updates.iter().filter(|u| u.security).count(),
        result.reboot_required
    );
    assert!(result
        .updates
        .iter()
        .all(|u| !u.name.is_empty() && !u.available_version.is_empty()));
}
