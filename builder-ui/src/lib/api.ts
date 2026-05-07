// Thin wrapper around the backend HTTP API.

import type { ArtifactCategory, Bundle, BuildSpec } from './types';

const BASE = '/api';

async function jpost<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`${path} failed: ${r.status} ${text}`);
  }
  return r.json() as Promise<T>;
}

async function jget<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json() as Promise<T>;
}

export const api = {
  artifacts: () => jget<ArtifactCategory[]>('/artifacts'),
  bundles:   () => jget<Bundle[]>('/bundles'),

  generateKeypair: (bits: 2048 | 3072 | 4096 = 4096) =>
    jpost<{ publicKeyPem: string; privateKeyPem: string; fingerprintSha256: string; generatedAtMs: number; bits: number }>(
      '/keypair/generate', { bits },
    ),

  generateIamPolicy: (input: { bucket: string; kmsKeyArn?: string; accessKeyId?: string }) =>
    jpost<unknown>('/aws/iam-policy', input),

  validateS3: (cfg: { bucket: string; region: string; accessKeyId: string; secretAccessKey: string; endpoint?: string; sseKmsKeyId?: string }) =>
    jpost<{ ok: boolean; status?: number; note?: string; error?: string; testKey?: string }>('/aws/validate', cfg),

  startBuild: (spec: BuildSpec) =>
    jpost<{ buildId: string; statusUrl: string; downloadUrl: string }>('/build', spec),

  // SSE log stream — returns an EventSource; caller wires up listeners.
  logStream: (buildId: string) => new EventSource(`${BASE}/build/${buildId}/stream`),

  downloadUrl: (buildId: string) => `${BASE}/build/${buildId}/download`,

  builds: () => jget<unknown[]>('/builds'),
};
