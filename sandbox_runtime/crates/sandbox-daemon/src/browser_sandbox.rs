use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// ROADMAP п.10/п.11: minimal bwrap filesystem view for the browser worker.
///
/// Goals:
/// - hostile web content rendered by Chromium must not see the real `/workspace`
///   (sources, .git, artifacts);
/// - only a dedicated per-audit output dir is writable and visible;
/// - network namespace is preserved (DAST needs egress via managed proxy/Tor),
///   but pid/ipc/uts are isolated and /usr is read-only.
///
/// If bwrap is unavailable, callers fall back to the legacy setpriv path.
pub fn command(output_dir: &Path) -> Result<Command, std::io::Error> {
    if !output_dir.is_dir() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!("browser output dir does not exist: {}", output_dir.display()),
        ));
    }
    if !Path::new("/usr/bin/bwrap").is_file() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            "bwrap binary not available for browser isolation",
        ));
    }

    let mut process = Command::new("/usr/bin/bwrap");
    process
        .arg("--die-with-parent")
        .arg("--new-session")
        .arg("--unshare-pid")
        .arg("--unshare-ipc")
        .arg("--unshare-uts")
        .arg("--hostname")
        .arg("browser-audit")
        .arg("--ro-bind")
        .arg("/usr")
        .arg("/usr");

    for (target, link) in [
        ("/usr/lib", "/lib"),
        ("/usr/lib64", "/lib64"),
        ("/usr/lib32", "/lib32"),
        ("/usr/bin", "/bin"),
        ("/usr/sbin", "/sbin"),
    ] {
        if Path::new(target).exists() {
            let rel_target = target.trim_start_matches('/');
            process.arg("--symlink").arg(rel_target).arg(link);
        }
    }

    process
        .arg("--tmpfs")
        .arg("/usr/local")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        // Chromium needs functional /dev/shm; --dev gives tmpfs, ensure shm dir exists.
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--dir")
        .arg("/etc")
        .arg("--dir")
        .arg("/etc/ssl")
        .arg("--dir")
        .arg("/run");

    for certs in ["/etc/ssl/certs", "/etc/ssl/certs/ca-certificates.crt"] {
        if Path::new(certs).exists() {
            if Path::new(certs).is_dir() {
                process.arg("--ro-bind").arg(certs).arg(certs);
            } else {
                process.arg("--ro-bind").arg(certs).arg(certs);
            }
        }
    }
    for etc_file in ["resolv.conf", "hosts", "nsswitch.conf", "passwd", "group"] {
        let src = Path::new("/etc").join(etc_file);
        if src.is_file() {
            process
                .arg("--ro-bind")
                .arg(&src)
                .arg(format!("/etc/{etc_file}"));
        }
    }

    // Trusted stealth runtime is read-only inside the view.
    if Path::new("/opt/stealth").is_dir() {
        process
            .arg("--ro-bind")
            .arg("/opt/stealth")
            .arg("/opt/stealth");
    }
    // Node binary needed to run the launcher.
    if Path::new("/opt/stealth/node_modules").is_dir() {
        // Already covered by /opt/stealth ro-bind; keep explicit for clarity.
    }

    // Isolated workspace: empty tmpfs with only the per-audit reports bind.
    // Real /workspace sources are never projected.
    // NOTE: output_dir lives under /var/tmp (see isolated_output_dir), NOT /tmp,
    // because /tmp is replaced by a fresh tmpfs above — a source under /tmp
    // would be hidden before the bind is evaluated and bwrap would fail.
    process.arg("--tmpfs").arg("/workspace");
    process.arg("--dir").arg("/workspace/reports");
    process
        .arg("--bind")
        .arg(output_dir)
        .arg("/workspace/reports");

    // Also expose the same output at /tmp/browser-reports for launchers
    // defaulting there. Destination parent first, then the bind.
    process.arg("--dir").arg("/tmp/browser-reports");
    process
        .arg("--bind")
        .arg(output_dir)
        .arg("/tmp/browser-reports");

    process.arg("--chdir").arg("/tmp");

    process
        .env_clear()
        .env("HOME", "/tmp")
        .env("XDG_CONFIG_HOME", "/tmp")
        .env("XDG_CACHE_HOME", "/tmp")
        .env("USER", "audit-browser")
        .env("LOGNAME", "audit-browser")
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
        .env("CHROMIUM_PATH", "/usr/lib/chromium/chromium")
        .env("NODE_PATH", "/opt/stealth/node_modules");

    Ok(process)
}

/// Probes once whether bwrap can actually create its mount/pid namespaces here.
/// Docker Desktop and similarly constrained runtimes reject pivot_root even with
/// CAP_SYS_ADMIN; in that case callers must fall back to the legacy setpriv
/// path instead of failing the audit outright.
pub fn is_bwrap_functional() -> bool {
    static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBE.get_or_init(|| {
        let probe = std::process::Command::new("/usr/bin/bwrap")
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--unshare-pid")
            .arg("--")
            .arg("/bin/true")
            .output();
        matches!(probe, Ok(out) if out.status.success())
    })
}

/// Returns an isolated per-audit output dir, creating it if needed.
///
/// Lives under /var/tmp on Linux (NOT /tmp): the bwrap view replaces /tmp with
/// a fresh tmpfs, which would hide a source dir under /tmp before binds are
/// evaluated. /var/tmp survives the tmpfs replacement. Falls back to the OS
/// temp dir on non-Linux dev hosts.
pub fn isolated_output_dir(audit_id: &str) -> Result<PathBuf, std::io::Error> {
    let sanitized: String = audit_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let base = if cfg!(target_os = "linux") {
        PathBuf::from("/var/tmp")
    } else {
        std::env::temp_dir()
    };
    let dir = base.join(format!(
        "browser-audit-{}-{}",
        sanitized.chars().take(32).collect::<String>(),
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_output_dir_sanitizes_audit_id() {
        let dir = isolated_output_dir("../../etc/passwd").unwrap();
        let s = dir.to_string_lossy();
        assert!(!s.contains(".."));
        assert!(s.contains("browser-audit-"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
