//! Runs against a local sshd when QK_SSH_TEST_PORT, QK_SSH_TEST_KEY and
//! QK_SSH_TEST_FINGERPRINT are set; otherwise the test is skipped.

use std::sync::Arc;
use std::time::Duration;

use qk_ssh::{connect, Command, SshError, Target, TrustPolicy};

fn env() -> Option<(Target, Arc<russh::keys::PrivateKey>, String)> {
    let port = std::env::var("QK_SSH_TEST_PORT").ok()?.parse().ok()?;
    let key = russh::keys::load_secret_key(std::env::var("QK_SSH_TEST_KEY").ok()?, None).ok()?;
    let fp = std::env::var("QK_SSH_TEST_FINGERPRINT").ok()?;
    let user = std::env::var("USER").ok()?;
    Some((Target { address: "127.0.0.1".into(), port, username: user }, Arc::new(key), fp))
}

#[tokio::test]
async fn host_key_policy_and_exec() {
    let Some((target, key, fp)) = env() else {
        eprintln!("skipped: local sshd not configured");
        return;
    };
    let t = Duration::from_secs(10);

    match connect(&target, key.clone(), TrustPolicy::Discover, t).await {
        Err(SshError::UnknownHostKey { fingerprint, .. }) => assert_eq!(fingerprint, fp),
        other => panic!("expected UnknownHostKey, got {:?}", other.err()),
    }

    let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    match connect(&target, key.clone(), TrustPolicy::Pinned(wrong.clone()), t).await {
        Err(SshError::HostKeyMismatch { expected, actual }) => {
            assert_eq!(expected, wrong);
            assert_eq!(actual, fp);
        }
        other => panic!("expected HostKeyMismatch, got {:?}", other.err()),
    }

    let conn = connect(&target, key, TrustPolicy::Pinned(fp.clone()), t).await.unwrap();
    assert_eq!(conn.host_key, fp);
    let out = conn.run(&Command::new("printf").args(["%s|", "a b", "$(id)", "x'y"])).await.unwrap();
    assert!(out.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "a b|$(id)|x'y|");
    let out = conn.run(&Command::new("sh").args(["-c", "exit 3"])).await.unwrap();
    assert_eq!(out.exit_status, Some(3));
    conn.close().await.unwrap();
}
