//! One-time access setup: installs QuietKeep's public key and, if the user asks, the
//! exact-command sudoers rule. Values are passed as positional shell arguments, never interpolated.

use qk_ssh::{Command, Connection, Result};

use crate::{tail, ActionReport, SUDOERS_PATH};

const INSTALL_KEY: &str = r#"umask 077
d="$HOME/.ssh"; f="$d/authorized_keys"
[ -d "$d" ] || mkdir -p "$d" || exit 1
[ "$(stat -c %a "$d")" = 700 ] || chmod 700 "$d" || exit 1
[ -f "$f" ] || touch "$f" || exit 1
[ "$(stat -c %a "$f")" = 600 ] || chmod 600 "$f" || exit 1
grep -qxF "$1" "$f" || printf '%s\n' "$1" >> "$f""#;

const INSTALL_SUDOERS: &str = r#"tmp=$(mktemp) || exit 1
printf '%s' "$1" > "$tmp" && visudo -cf "$tmp" >/dev/null && install -m 0440 -o root -g root "$tmp" "$2"
rc=$?; rm -f "$tmp"; exit $rc"#;

pub fn install_key_command(public_key: &str) -> Command {
    Command::new("sh").args(["-c", INSTALL_KEY, "sh", public_key.trim()])
}

pub fn install_sudoers_command(rule: &str, as_root: bool) -> Command {
    let base = if as_root {
        Command::new("sh")
    } else {
        Command::new("sudo").args(["-S", "-p", "", "--", "sh"])
    };
    base.args(["-c", INSTALL_SUDOERS, "sh", rule, SUDOERS_PATH])
}

/// Plain-language steps shown to the user before they confirm.
pub fn describe(use_agent: bool, install_sudoers: bool, as_root: bool) -> Vec<String> {
    let login = if use_agent {
        "Log in once with your own SSH key through your ssh-agent. Your key never leaves the agent."
    } else {
        "Log in once with the password you enter. The password is not saved."
    };
    let mut steps = vec![
        login.to_string(),
        "Create ~/.ssh with mode 700 and authorized_keys with mode 600 if needed.".to_string(),
        "Add QuietKeep's public key to ~/.ssh/authorized_keys if it is not already there."
            .to_string(),
    ];
    if install_sudoers {
        steps.push(format!(
            "{}check the rule below with visudo and install it as {SUDOERS_PATH} (mode 440).",
            match (as_root, use_agent) {
                (true, _) => "As root, ",
                (false, true) => "Using sudo with the sudo password you enter (not saved), ",
                (false, false) => "Using sudo with the same password, ",
            }
        ));
    }
    steps
}

pub async fn install_key(conn: &Connection, public_key: &str) -> Result<ActionReport> {
    let out = conn.run(&install_key_command(public_key)).await?;
    let mut log = out.stdout.clone();
    log.extend_from_slice(&out.stderr);
    Ok(ActionReport {
        success: out.success(),
        output_tail: tail(&log),
    })
}

pub async fn install_sudoers(
    conn: &Connection,
    rule: &str,
    password: &str,
    as_root: bool,
) -> Result<ActionReport> {
    let input = format!("{password}\n");
    let stdin = (!as_root).then_some(input.as_bytes());
    let out = conn
        .run_with_stdin(&install_sudoers_command(rule, as_root), stdin)
        .await?;
    let mut log = out.stdout.clone();
    log.extend_from_slice(&out.stderr);
    Ok(ActionReport {
        success: out.success(),
        output_tail: tail(&log),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_a_positional_argument() {
        let cmd = install_key_command("ssh-ed25519 AAAA'x quietkeep\n");
        assert!(cmd.as_str().starts_with("sh -c "));
        assert!(cmd
            .as_str()
            .ends_with(r#" sh 'ssh-ed25519 AAAA'\''x quietkeep'"#));
    }

    #[test]
    fn sudoers_uses_sudo_unless_root() {
        assert!(install_sudoers_command("r", false)
            .as_str()
            .starts_with("sudo -S -p '' -- sh -c "));
        assert!(install_sudoers_command("r", true)
            .as_str()
            .starts_with("sh -c "));
        assert!(install_sudoers_command("r", true)
            .as_str()
            .ends_with(" sh r /etc/sudoers.d/quietkeep"));
    }
}
