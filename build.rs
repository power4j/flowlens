use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }

    let commit = git_short_hash().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FLOWLENS_BUILD_COMMIT={commit}");
    println!("cargo:rerun-if-changed=.git/HEAD");
}

fn git_short_hash() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hash = String::from_utf8(output.stdout).ok()?;
    let hash = hash.trim();
    if hash.is_empty() {
        None
    } else {
        Some(hash.to_string())
    }
}
