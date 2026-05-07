// Build script: embeds an admin-required manifest into the resulting EXE
// so Windows triggers a UAC prompt automatically when a non-elevated user
// double-clicks Collector.exe. When run from a SYSTEM-context GPO startup
// script, this is a no-op (already elevated).

#[cfg(target_os = "windows")]
fn main() {
    use embed_manifest::{embed_manifest, new_manifest};
    use embed_manifest::manifest::{ExecutionLevel, SupportedOS};

    let manifest = new_manifest("DFIR.Collector")
        .ui_access(false)
        .requested_execution_level(ExecutionLevel::RequireAdministrator)
        .supported_os(SupportedOS::Windows7..=SupportedOS::Windows10);

    if let Err(e) = embed_manifest(manifest) {
        println!("cargo:warning=embed-manifest failed: {e}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/embedded_config.json");
}

#[cfg(not(target_os = "windows"))]
fn main() {}
