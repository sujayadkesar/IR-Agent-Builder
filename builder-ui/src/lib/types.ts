// Shared types between UI and backend (v2 — supports Linux + custom artifacts + chunk upload).

export interface ArtifactParamOption {
  value: string;
  label: string;
  desc?: string;
  sizeMul?: number;
  size_mul?: number; // YAML format
}

export interface ArtifactParam {
  key: string;
  label: string;
  type: 'select' | 'number' | 'boolean' | 'string';
  default: string | number | boolean;
  options?: ArtifactParamOption[];
  min?: number;
  max?: number;
  step?: number;
  suffix?: string;
  placeholder?: string;
}

export interface ArtifactItem {
  id: string;
  yamlName?: string;
  name: string;
  desc: string;
  sizeMb: number;
  timeSec: number;
  deps: string[];
  params?: ArtifactParam[];
  platform?: 'windows' | 'linux' | 'all';
  isCustom?: boolean;
  author?: string;
  version?: string;
  references?: string[];
  sourceCount?: number;
}

export type ArtifactParamValues = Record<string, Record<string, string | number | boolean>>;

export interface ArtifactCategory {
  category: string;
  items: ArtifactItem[];
}

export interface Bundle {
  id: string;
  name: string;
  estimateLabel?: string;
  estimate_label?: string;
  color: string;
  description: string;
  artifacts: string[];
  kapeTargets?: string[];
  kape_targets?: string[];
  platform?: string;
}

export type UploadKind = 'local' | 's3';
export type TargetPlatform = 'windows' | 'linux';

export interface UploadConfig {
  kind: UploadKind;
  localPath?: string;
  bucket?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  endpoint?: string;
  sseKmsKeyId?: string;
  verifyTls?: boolean;
  prefixTemplate?: string;
}

export interface EncryptionConfig {
  scheme: 'x509' | 'none';
  publicKeyPem?: string;
  privateKeyPem?: string;
  fingerprintSha256?: string;
}

export interface ChunkUploadConfig {
  enabled: boolean;
  chunkSizeMb: number;
  streamMode: boolean;
  lowDiskThresholdMb: number;
}

export interface BuildSpec {
  // Step 1 — Target
  siteCode: string;
  filenameTemplate: string;
  uuidSuffix: boolean;
  targetPlatform: TargetPlatform;

  // Step 2 — Artifacts
  artifacts: string[];
  artifactParams: ArtifactParamValues;
  kapeTargets: string[];
  useVss: boolean;

  // Step 3 — Upload
  upload: UploadConfig;
  chunkUpload: ChunkUploadConfig;

  // Step 4 — Encryption & Security
  encryption: EncryptionConfig;
  requireAdmin: boolean;
  silent: boolean;
  deleteAfterUpload: boolean;

  // Step 5 — Performance
  cpuLimitPercent: number;
  concurrency: number;
  progressTimeoutSeconds: number;
  outputFormat: 'jsonl' | 'csv';
  maxCollectionSizeGb: number;
}

// Custom artifact creation
export interface CustomArtifactValidation {
  valid: boolean;
  errors: string[];
  parsed: any;
}

export interface CustomArtifactSaveResult {
  ok: boolean;
  filePath: string;
  artifact: any;
}
