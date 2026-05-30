//! YAML artifact catalog loader. Walks `artifacts/**/*.yaml`, parses each
//! definition, exposes the catalog grouped by category, and produces the
//! `embedded_sources` map that gets baked into the collector binary.
//!
//! Direct port of `builder-server/src/lib/artifact-loader.js` with stricter
//! typing.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Names of files under `artifacts/` that are NOT artifact definitions.
const SKIP_FILENAMES: &[&str] = &["schema.yaml", "bundles.yaml", "TEMPLATE.yaml"];

/// IDs in the legacy catalog dropped the `windows.` prefix. We do the same
/// here so the collector's hardcoded match arms keep working.
const LEGACY_PREFIX: &str = "windows.";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactParamOption {
    pub value: String,
    pub label: String,
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default)]
    pub size_mul: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactParam {
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub default: serde_json::Value,
    #[serde(default)]
    pub options: Vec<ArtifactParamOption>,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    #[serde(default)]
    pub step: Option<f64>,
    #[serde(default)]
    pub suffix: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawArtifact {
    name: String,
    display: String,
    #[serde(default)]
    description: String,
    platform: String,
    #[serde(rename = "type")]
    artifact_type: String,
    category: String,
    #[serde(default)]
    author: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    deps: Vec<String>,
    #[serde(default)]
    size_mb: u64,
    #[serde(default)]
    time_sec: u64,
    #[serde(default)]
    params: Vec<ArtifactParam>,
    #[serde(default)]
    sources: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ArtifactDef {
    /// User-facing ID (legacy-stripped). e.g. `execution.prefetch`.
    pub id: String,
    /// Raw `name` field from YAML. e.g. `windows.execution.prefetch`.
    pub yaml_name: String,
    pub display: String,
    pub description: String,
    pub platform: String,
    pub artifact_type: String,
    pub category: String,
    pub author: String,
    pub version: String,
    pub references: Vec<String>,
    pub deps: Vec<String>,
    pub size_mb: u64,
    pub time_sec: u64,
    pub params: Vec<ArtifactParam>,
    pub sources: Vec<serde_json::Value>,
    pub file_path: PathBuf,
    pub is_custom: bool,
}

#[derive(Debug, Clone)]
pub struct CategoryGroup {
    pub category: String,
    pub items: Vec<ArtifactDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleDef {
    pub id: String,
    pub name: String,
    pub platform: String,
    #[serde(default)]
    pub estimate_label: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub kape_targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Catalog {
    pub artifacts: HashMap<String, ArtifactDef>,
    pub bundles: Vec<BundleDef>,
    pub root: PathBuf,
}

impl Catalog {
    pub fn load(artifacts_root: impl AsRef<Path>) -> Result<Self> {
        let root = artifacts_root.as_ref().to_path_buf();
        let artifacts = scan_artifacts(&root)?;
        let bundles = load_bundles(&root).unwrap_or_default();
        log::info!(
            "[catalog] loaded {} artifacts, {} bundles from {}",
            artifacts.len(),
            bundles.len(),
            root.display()
        );
        Ok(Self {
            artifacts,
            bundles,
            root,
        })
    }

    pub fn for_platform(&self, platform: &str) -> Vec<CategoryGroup> {
        let mut groups: HashMap<String, Vec<ArtifactDef>> = HashMap::new();
        for a in self.artifacts.values() {
            if a.platform != platform && a.platform != "all" {
                continue;
            }
            groups.entry(a.category.clone()).or_default().push(a.clone());
        }
        let mut groups: Vec<CategoryGroup> = groups
            .into_iter()
            .map(|(category, mut items)| {
                items.sort_by(|a, b| a.display.cmp(&b.display));
                CategoryGroup { category, items }
            })
            .collect();
        groups.sort_by(|a, b| a.category.cmp(&b.category));
        groups
    }

    pub fn bundles_for_platform(&self, platform: &str) -> Vec<&BundleDef> {
        self.bundles
            .iter()
            .filter(|b| b.platform == platform || b.platform == "all")
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<&ArtifactDef> {
        self.artifacts.get(id)
    }

    /// Build the `embedded_sources` map that the collector reads at runtime.
    /// Template variables in globs (e.g. `{{profile}}`) are resolved against
    /// the user-provided per-artifact params.
    pub fn to_embedded_format(
        &self,
        artifact_ids: &[String],
        params: &HashMap<String, HashMap<String, serde_json::Value>>,
    ) -> HashMap<String, serde_json::Value> {
        let mut embedded = HashMap::new();
        for id in artifact_ids {
            let Some(artifact) = self.artifacts.get(id) else {
                log::warn!("[catalog] unknown artifact id at embed time: {id}");
                continue;
            };
            let entry_params = params.get(id);
            let resolved_sources: Vec<serde_json::Value> = artifact
                .sources
                .iter()
                .map(|src| resolve_source(src, entry_params))
                .collect();
            embedded.insert(
                id.clone(),
                serde_json::json!({
                    "type": artifact.artifact_type,
                    "platform": artifact.platform,
                    "sources": resolved_sources,
                }),
            );
        }
        embedded
    }
}

fn resolve_source(
    src: &serde_json::Value,
    params: Option<&HashMap<String, serde_json::Value>>,
) -> serde_json::Value {
    let mut resolved = src.clone();
    let Some(template_vars) = src.get("template_vars").and_then(|v| v.as_object()) else {
        return resolved;
    };
    let Some(globs) = src.get("globs").and_then(|v| v.as_array()) else {
        return resolved;
    };

    let new_globs: Vec<serde_json::Value> = globs
        .iter()
        .filter_map(|g| g.as_str())
        .map(|glob| {
            let mut s = glob.to_string();
            for (var_name, var_def) in template_vars {
                let from_param = var_def
                    .get("from_param")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let map = var_def
                    .get("map")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();

                let chosen_param = params
                    .and_then(|p| p.get(from_param))
                    .and_then(|v| v.as_str());

                let replacement: String = chosen_param
                    .and_then(|k| map.get(k))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| {
                        map.values()
                            .next()
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_default();

                s = s.replace(&format!("{{{{{var_name}}}}}"), &replacement);
            }
            serde_json::Value::String(s)
        })
        .collect();

    if let Some(obj) = resolved.as_object_mut() {
        obj.insert("globs".to_string(), serde_json::Value::Array(new_globs));
    }
    resolved
}

fn scan_artifacts(root: &Path) -> Result<HashMap<String, ArtifactDef>> {
    let mut map = HashMap::new();
    if !root.exists() {
        return Ok(map);
    }
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("yaml") {
            continue;
        }
        let fname = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if SKIP_FILENAMES.contains(&fname) {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("[catalog] read {} failed: {e}", path.display());
                continue;
            }
        };
        let raw: RawArtifact = match serde_yaml::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("[catalog] parse {} failed: {e}", path.display());
                continue;
            }
        };
        if raw.name == "custom.my_artifact" {
            continue; // template marker
        }
        let id = raw
            .name
            .strip_prefix(LEGACY_PREFIX)
            .map(String::from)
            .unwrap_or_else(|| raw.name.clone());
        let is_custom = path
            .components()
            .any(|c| c.as_os_str() == OsStr::new("custom"));
        let def = ArtifactDef {
            id: id.clone(),
            yaml_name: raw.name,
            display: raw.display,
            description: raw.description,
            platform: raw.platform,
            artifact_type: raw.artifact_type,
            category: raw.category,
            author: raw.author,
            version: raw.version,
            references: raw.references,
            deps: raw.deps,
            size_mb: raw.size_mb,
            time_sec: raw.time_sec,
            params: raw.params,
            sources: raw.sources,
            file_path: path.to_path_buf(),
            is_custom,
        };
        map.insert(id, def);
    }
    Ok(map)
}

fn load_bundles(root: &Path) -> Result<Vec<BundleDef>> {
    let p = root.join("bundles.yaml");
    if !p.exists() {
        return Ok(Vec::new());
    }
    #[derive(Deserialize)]
    struct Wrapper {
        bundles: Vec<BundleDef>,
    }
    let content = std::fs::read_to_string(&p)?;
    let w: Wrapper = serde_yaml::from_str(&content)?;
    Ok(w.bundles)
}
