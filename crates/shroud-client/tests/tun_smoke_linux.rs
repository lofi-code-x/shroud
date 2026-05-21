use std::path::Path;
use tokio::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "Linux-only TUN smoke; requires sudo/root and is not part of the default MVP gate"]
async fn sudo_tun_smoke_linux_script() -> TestResult {
    let output = Command::new("id").arg("-u").output().await?;
    let uid = String::from_utf8_lossy(&output.stdout);
    if uid.trim() != "0" {
        return Err(
            "Linux TUN smoke requires root; run `sudo ./scripts/tun-smoke-linux.sh`".into(),
        );
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("failed to locate workspace root")?;
    let script = workspace_root.join("scripts/tun-smoke-linux.sh");
    let status = Command::new(&script).status().await?;

    assert!(
        status.success(),
        "TUN smoke script failed: {}",
        script.display()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
#[ignore = "Linux-only TUN smoke; not part of the default MVP gate"]
async fn sudo_tun_smoke_linux_script() -> TestResult {
    Ok(())
}
