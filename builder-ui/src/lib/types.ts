// Shared types between UI and backend.

export interface ArtifactParamOption {
  value: string;
  label: string;
  desc?: string;
  sizeMul?: number;
}

export interface ArtifactParam {
  key: string;
  label: string;
  type: 'select' | 'number' | 'boolean';
  default: string | number | boolean;
  options?: ArtifactParamOption[];
  min?: number;
  max?: number;
  step?: number;
  suffix?: string;
}

export interface ArtifactItem {
  id: string;
  name: string;
  desc: string;
  sizeMb: number;
  timeSec: number;
  deps: string[];
  params?: ArtifactParam[];
}

/// Per-artifact parameter selections. Keyed by artifact id.
/// Each value is a small object whose keys are param.key and values are
/// the user's selection (string for select, number for number, bool for boolean).
export type ArtifactParamValues = Record<string, Record<string, string | number | boolean>>;

export interface ArtifactCategory {
  category: string;
  items: ArtifactItem[];
}

export interface Bundle {
  id: string;
  name: string;
  estimateLabel: string;
  color: string;
  description: string;
  artifacts: string[];
  kapeTargets: string[];
}

export type UploadKind = 'local' | 's3';

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
  privateKeyPem?: string;        // never sent to backend on build, only kept in memory for download
  fingerprintSha256?: string;
}

export interface BuildSpec {
  // Step 1
  siteCode: string;
  filenameTemplate: string;
  uuidSuffix: boolean;
  targetOs: 'win64' | 'win32';

  // Step 2
  artifacts: string[];
  artifactParams: ArtifactParamValues;
  kapeTargets: string[];
  useVss: boolean;

  // Step 3
  upload: UploadConfig;

  // Step 4
  encryption: EncryptionConfig;
  requireAdmin: boolean;
  silent: boolean;
  deleteAfterUpload: boolean;

  // Step 5
  cpuLimitPercent: number;
  concurrency: number;
  progressTimeoutSeconds: number;
  outputFormat: 'jsonl' | 'csv';
  maxCollectionSizeGb: number;
}
