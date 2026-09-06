use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use tokio::process::Command;

const PRIVATE_RUNTIME_ROOT: &str = "/opt/evolve-private";

pub fn command(
    synthetic_root: &Path,
    include_private_runtime: bool,
) -> Result<Command, std::io::Error> {
    if !synthetic_root.is_dir() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            "synthetic deception root does not exist",
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
        .arg("prod-app-01")
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
        // /usr/local contains the trusted sandbox daemon. Never project it into a deceptive shell.
        .arg("--tmpfs")
        .arg("/usr/local")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--dir")
        .arg("/etc")
        .arg("--dir")
        .arg("/etc/ssl")
        .arg("--dir")
        .arg("/run");

    if Path::new("/etc/ssl/certs").is_dir() {
        process
            .arg("--ro-bind")
            .arg("/etc/ssl/certs")
            .arg("/etc/ssl/certs");
    }

    for file in ["hosts", "hostname", "nsswitch.conf", "passwd", "group"] {
        let source = synthetic_root.join("etc").join(file);
        if !source.is_file() {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("missing synthetic /etc/{file}"),
            ));
        }
        process
            .arg("--ro-bind")
            .arg(source)
            .arg(format!("/etc/{file}"));
    }

    process
        .arg("--bind")
        .arg(synthetic_root)
        .arg("/workspace")
        .arg("--chdir")
        .arg("/workspace");

    if include_private_runtime {
        if !Path::new(PRIVATE_RUNTIME_ROOT).is_dir() {
            return Err(IoError::new(
                ErrorKind::NotFound,
                "private deception runtime directory is missing",
            ));
        }
        process
            .arg("--dir")
            .arg("/opt")
            .arg("--ro-bind")
            .arg(PRIVATE_RUNTIME_ROOT)
            .arg(PRIVATE_RUNTIME_ROOT);
    }

    process
        .env_clear()
        .env("HOME", "/workspace/home")
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8");

    Ok(process)
}
