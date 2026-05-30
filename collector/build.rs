// Build script: embeds an admin-required manifest into the resulting EXE
// so Windows triggers a UAC prompt automatically when a non-elevated user
// double-clicks Collector.exe. When run from a SYSTEM-context GPO startup
// script, this is a no-op (already elevated).
//
// The manifest is ONLY embedded in release builds. Debug + test builds skip
// it so the test runner can actually launch the binary without elevation
// (Windows error 740 otherwise).

#[cfg(target_os = "windows")]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/embedded_config.json");

    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile != "release" {
        return;
    }

    use embed_manifest::manifest::{ExecutionLevel, SupportedOS};
    use embed_manifest::{embed_manifest, new_manifest};

    let manifest = new_manifest("DFIR.Collector")
        .ui_access(false)
        .requested_execution_level(ExecutionLevel::RequireAdministrator)
        .supported_os(SupportedOS::Windows7..=SupportedOS::Windows10);

    if let Err(e) = embed_manifest(manifest) {
        println!("cargo:warning=embed-manifest failed: {e}");
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {}
