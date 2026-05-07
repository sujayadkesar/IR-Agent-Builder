// Credential Vault — build-time encryption of AWS secrets.
//
// Produces an encrypted blob that gets embedded in the collector binary.
// The collector reverses the process at runtime using the build_id and
// build_timestamp as key derivation material.
//
// This prevents secrets from appearing as plaintext strings in the binary,
// defeating `strings`, Ghidra, and automated credential scanners.

import { createCipheriv, randomBytes, createHash, createHmac } from 'node:crypto';

const VAULT_MARKER = Buffer.from('DFIRV001', 'ascii');

/**
 * Encrypt AWS credentials into a vault blob.
 *
 * @param {object} creds - { accessKeyId, secretAccessKey }
 * @param {string} buildId - unique build identifier
 * @param {string} buildTimestamp - ISO timestamp
 * @returns {{ vaultBlob: Buffer, vaultHmac: Buffer, vaultBase64: string }}
 */
export function encryptCredentials(creds, buildId, buildTimestamp) {
  const plaintext = Buffer.from(JSON.stringify({
    a: creds.accessKeyId,
    s: creds.secretAccessKey,
  }));

  // Derive XOR key from build identity
  const derivationMaterial = `${buildId}:${buildTimestamp}`;
  const masterHash = createHash('sha256').update(derivationMaterial).digest();
  const xorKey = masterHash.subarray(0, 8);

  // Generate random AES-256 key
  const aesKey = randomBytes(32);
  const nonce = randomBytes(12);

  // Split key into 4 fragments and XOR each with the derivation key
  const frag1 = Buffer.alloc(8);
  const frag2 = Buffer.alloc(8);
  const frag3 = Buffer.alloc(8);
  const frag4 = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) {
    frag1[i] = aesKey[i] ^ xorKey[i];
    frag2[i] = aesKey[8 + i] ^ xorKey[i];
    frag3[i] = aesKey[16 + i] ^ xorKey[i];
    frag4[i] = aesKey[24 + i] ^ xorKey[i];
  }

  // AES-256-GCM encrypt
  const cipher = createCipheriv('aes-256-gcm', aesKey, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([encrypted, authTag]);

  // Assemble vault blob: MARKER + nonce(12) + frag1(8) + frag2(8) + frag3(8) + frag4(8) + ciphertext
  const vaultBlob = Buffer.concat([
    VAULT_MARKER,
    nonce,
    frag1,
    frag2,
    frag3,
    frag4,
    ciphertext,
  ]);

  // HMAC for integrity verification
  const hmac = createHmac('sha256', buildId);
  hmac.update(vaultBlob);
  const vaultHmac = hmac.digest();

  // Zero sensitive material
  aesKey.fill(0);

  return {
    vaultBlob,
    vaultHmac,
    vaultBase64: vaultBlob.toString('base64'),
    hmacHex: vaultHmac.toString('hex'),
  };
}

/**
 * Generate an embedded config where AWS credentials are vaulted.
 * The S3 config no longer has plaintext access_key_id / secret_access_key.
 * Instead it has vault_blob (base64) and vault_hmac (hex).
 */
export function vaultifyConfig(config, buildId, buildTimestamp) {
  if (config.upload?.kind !== 's3' || !config.upload?.s3) return config;

  const s3 = config.upload.s3;
  if (!s3.access_key_id || !s3.secret_access_key) return config;

  const { vaultBase64, hmacHex } = encryptCredentials(
    { accessKeyId: s3.access_key_id, secretAccessKey: s3.secret_access_key },
    buildId,
    buildTimestamp,
  );

  const vaultedS3 = {
    ...s3,
    access_key_id: '',       // cleared — vault replaces these
    secret_access_key: '',   // cleared
    credential_vault: vaultBase64,
    credential_vault_hmac: hmacHex,
  };

  return {
    ...config,
    upload: {
      ...config.upload,
      s3: vaultedS3,
    },
  };
}
