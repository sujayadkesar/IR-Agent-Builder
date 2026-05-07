// YAML Artifact Loader — reads all .yaml files under the artifacts/ directory
// tree and builds the runtime catalog. Supports hot-reload for custom artifacts
// added while the server is running.
//
// This replaces the hardcoded ARTIFACT_CATALOG in catalog.js with a dynamic
// system modeled after Velociraptor's artifact definition engine.

import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

const ARTIFACTS_ROOT = path.resolve(
  path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/i, '$1'),
  '..', '..', '..', 'artifacts'
);

export class ArtifactRegistry {
  constructor() {
    this.artifacts = new Map();
    this.categories = new Map();
    this.lastLoadTime = null;
    this.watchInterval = null;
  }

  load() {
    this.artifacts.clear();
    this.categories.clear();
    const yamlFiles = this._findYamlFiles(ARTIFACTS_ROOT);
    let loaded = 0;
    let errors = 0;

    for (const filePath of yamlFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const def = yaml.load(content);
        if (!def || !def.name || !def.display || !def.platform || !def.sources) {
          console.warn(`[artifact-loader] skipping ${filePath}: missing required fields`);
          errors++;
          continue;
        }
        if (def.name === 'custom.my_artifact') continue; // skip template

        const artifact = this._normalize(def, filePath);
        this.artifacts.set(artifact.id, artifact);

        if (!this.categories.has(artifact.category)) {
          this.categories.set(artifact.category, []);
        }
        this.categories.get(artifact.category).push(artifact);
        loaded++;
      } catch (e) {
        console.error(`[artifact-loader] error parsing ${filePath}: ${e.message}`);
        errors++;
      }
    }
    this.lastLoadTime = new Date();
    console.log(`[artifact-loader] loaded ${loaded} artifacts from ${ARTIFACTS_ROOT} (${errors} errors)`);
    return this;
  }

  startWatching(intervalMs = 10000) {
    this.watchInterval = setInterval(() => {
      const customDir = path.join(ARTIFACTS_ROOT, 'custom');
      if (!fs.existsSync(customDir)) return;
      const stat = fs.statSync(customDir);
      if (stat.mtimeMs > this.lastLoadTime.getTime()) {
        console.log('[artifact-loader] custom artifacts changed, reloading...');
        this.load();
      }
    }, intervalMs);
  }

  stopWatching() {
    if (this.watchInterval) {
      clearInterval(this.watchInterval);
      this.watchInterval = null;
    }
  }

  getCatalog(platform = null) {
    const grouped = new Map();
    for (const [, artifact] of this.artifacts) {
      if (platform && artifact.platform !== platform && artifact.platform !== 'all') continue;
      if (!grouped.has(artifact.category)) {
        grouped.set(artifact.category, []);
      }
      grouped.get(artifact.category).push(artifact);
    }
    return Array.from(grouped.entries()).map(([category, items]) => ({
      category,
      items: items.map(a => this._toUiFormat(a)),
    }));
  }

  getLinuxCatalog() { return this.getCatalog('linux'); }
  getWindowsCatalog() { return this.getCatalog('windows'); }

  getArtifact(id) {
    return this.artifacts.get(id) || null;
  }

  getArtifactsByIds(ids) {
    return ids.map(id => this.artifacts.get(id)).filter(Boolean);
  }

  validateArtifactYaml(yamlContent) {
    try {
      const def = yaml.load(yamlContent);
      const errors = [];
      if (!def.name) errors.push('missing "name"');
      if (!def.display) errors.push('missing "display"');
      if (!def.platform) errors.push('missing "platform"');
      if (!def.sources || !Array.isArray(def.sources)) errors.push('missing or invalid "sources"');
      if (!def.type) errors.push('missing "type"');
      if (!def.category) errors.push('missing "category"');
      if (!['windows', 'linux', 'all'].includes(def.platform)) {
        errors.push(`invalid platform "${def.platform}" — must be windows, linux, or all`);
      }
      const validTypes = ['file_pattern', 'command', 'registry', 'raw_ntfs', 'composite'];
      if (!validTypes.includes(def.type)) {
        errors.push(`invalid type "${def.type}" — must be one of: ${validTypes.join(', ')}`);
      }
      if (def.sources) {
        for (const [i, src] of def.sources.entries()) {
          if (!src.type) errors.push(`source[${i}]: missing "type"`);
          if (src.type === 'file_pattern' && (!src.globs || !Array.isArray(src.globs))) {
            errors.push(`source[${i}]: file_pattern requires "globs" array`);
          }
          if (src.type === 'command' && !src.cmd) {
            errors.push(`source[${i}]: command requires "cmd"`);
          }
          if (src.type === 'registry' && (!src.hives || !Array.isArray(src.hives))) {
            errors.push(`source[${i}]: registry requires "hives" array`);
          }
        }
      }
      if (this.artifacts.has(def.name)) {
        errors.push(`artifact "${def.name}" already exists — use a unique name`);
      }
      return { valid: errors.length === 0, errors, parsed: def };
    } catch (e) {
      return { valid: false, errors: [`YAML parse error: ${e.message}`], parsed: null };
    }
  }

  saveCustomArtifact(yamlContent, filename) {
    const customDir = path.join(ARTIFACTS_ROOT, 'custom');
    fs.mkdirSync(customDir, { recursive: true });
    const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    const filePath = path.join(customDir, safeName.endsWith('.yaml') ? safeName : `${safeName}.yaml`);
    fs.writeFileSync(filePath, yamlContent, 'utf8');
    this.load();
    return filePath;
  }

  deleteCustomArtifact(artifactName) {
    const artifact = this.artifacts.get(artifactName);
    if (!artifact) return false;
    if (!artifact._filePath.includes(path.join('artifacts', 'custom'))) {
      throw new Error('can only delete custom artifacts');
    }
    fs.unlinkSync(artifact._filePath);
    this.load();
    return true;
  }

  exportArtifact(artifactName) {
    const artifact = this.artifacts.get(artifactName);
    if (!artifact) return null;
    return fs.readFileSync(artifact._filePath, 'utf8');
  }

  _normalize(def, filePath) {
    const legacyIdMap = {
      'windows.execution.prefetch': 'execution.prefetch',
      'windows.execution.amcache': 'execution.amcache',
      'windows.execution.shimcache': 'execution.shimcache',
      'windows.execution.bam': 'execution.bam',
      'windows.execution.userassist': 'execution.userassist',
      'windows.execution.muicache': 'execution.muicache',
      'windows.filesystem.mft': 'filesystem.mft',
      'windows.filesystem.lnk': 'filesystem.lnk',
      'windows.filesystem.recyclebin': 'filesystem.recyclebin',
      'windows.registry.hives': 'registry.hives',
      'windows.eventlogs.security': 'eventlogs.security',
      'windows.eventlogs.system': 'eventlogs.system',
      'windows.eventlogs.application': 'eventlogs.application',
      'windows.eventlogs.powershell': 'eventlogs.powershell',
      'windows.eventlogs.sysmon': 'eventlogs.sysmon',
      'windows.eventlogs.defender': 'eventlogs.defender',
      'windows.eventlogs.rdp': 'eventlogs.rdp',
      'windows.eventlogs.taskscheduler': 'eventlogs.taskscheduler',
      'windows.eventlogs.wmi': 'eventlogs.wmi',
      'windows.eventlogs.bits': 'eventlogs.bits',
      'windows.live.netstat': 'live.netstat',
      'windows.live.pslist': 'live.pslist',
      'windows.live.dnscache': 'live.dnscache',
      'windows.live.arpcache': 'live.arpcache',
      'windows.live.services': 'live.services',
      'windows.live.systeminfo': 'live.systeminfo',
      'windows.live.usbhistory': 'live.usbhistory',
      'windows.live.wifihistory': 'live.wifihistory',
      'windows.live.shares': 'live.shares',
      'windows.live.firewallrules': 'live.firewallrules',
      'windows.live.autoruns': 'live.autoruns',
      'windows.persistence.scheduledtasks': 'persistence.scheduledtasks',
      'windows.persistence.startupfolders': 'persistence.startupfolders',
      'windows.browser.chrome': 'browser.chrome',
      'windows.browser.edge': 'browser.edge',
      'windows.browser.firefox': 'browser.firefox',
      'windows.cloud.onedrive': 'cloud.onedrive',
      'windows.cloud.outlook': 'cloud.outlook',
      'windows.cloud.teams': 'cloud.teams',
      'windows.cred.dpapi': 'cred.dpapi',
      'windows.memory.fulldump': 'memory.fulldump',
    };

    const id = legacyIdMap[def.name] || def.name;

    return {
      id,
      yamlName: def.name,
      display: def.display,
      description: def.description || '',
      platform: def.platform,
      type: def.type,
      category: def.category,
      author: def.author || 'Unknown',
      version: def.version || '1.0.0',
      references: def.references || [],
      deps: def.deps || [],
      size_mb: def.size_mb || 0,
      time_sec: def.time_sec || 0,
      params: def.params || [],
      sources: def.sources || [],
      _filePath: filePath,
      _isCustom: filePath.includes(path.join('artifacts', 'custom')),
    };
  }

  _toUiFormat(artifact) {
    return {
      id: artifact.id,
      yamlName: artifact.yamlName,
      name: artifact.display,
      desc: artifact.description,
      sizeMb: artifact.size_mb,
      timeSec: artifact.time_sec,
      deps: artifact.deps,
      params: artifact.params.map(p => ({
        key: p.key,
        label: p.label,
        type: p.type,
        default: p.default,
        options: p.options,
        min: p.min,
        max: p.max,
        step: p.step,
        suffix: p.suffix,
        placeholder: p.placeholder,
      })),
      platform: artifact.platform,
      isCustom: artifact._isCustom,
      author: artifact.author,
      version: artifact.version,
      references: artifact.references,
      sourceCount: artifact.sources.length,
    };
  }

  _findYamlFiles(dir) {
    const results = [];
    if (!fs.existsSync(dir)) return results;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...this._findYamlFiles(fullPath));
      } else if (entry.name.endsWith('.yaml') && entry.name !== 'schema.yaml') {
        results.push(fullPath);
      }
    }
    return results;
  }

  toEmbeddedFormat(artifactIds, artifactParams = {}) {
    const artifacts = [];
    const embeddedSources = {};

    for (const id of artifactIds) {
      const artifact = this.artifacts.get(id);
      if (!artifact) {
        console.warn(`[artifact-loader] unknown artifact id: ${id}`);
        continue;
      }
      artifacts.push(id);
      embeddedSources[id] = {
        type: artifact.type,
        platform: artifact.platform,
        sources: artifact.sources.map(src => {
          const resolved = { ...src };
          if (src.template_vars) {
            resolved.globs = this._resolveTemplateVars(src.globs, src.template_vars, artifactParams[id] || {});
          }
          return resolved;
        }),
      };
    }

    return { artifacts, embeddedSources };
  }

  _resolveTemplateVars(globs, templateVars, params) {
    return globs.map(glob => {
      let resolved = glob;
      for (const [varName, varDef] of Object.entries(templateVars)) {
        const paramValue = params[varDef.from_param] || Object.keys(varDef.map)[0];
        const replacement = varDef.map[paramValue] || varDef.map[Object.keys(varDef.map)[0]];
        resolved = resolved.replace(new RegExp(`\\{\\{${varName}\\}\\}`, 'g'), replacement);
      }
      return resolved;
    });
  }
}

export function createRegistry() {
  const registry = new ArtifactRegistry();
  registry.load();
  registry.startWatching();
  return registry;
}
