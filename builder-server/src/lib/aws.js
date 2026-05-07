// AWS helpers: IAM policy generator + S3 connection validator.
//
// IAM policy follows §3.3 of the research doc — write-only, scoped to a
// per-user prefix, KMS-encrypted only.
//
// Validation makes a tiny PutObject (16 bytes) to a sentinel key and then
// either issues a DeleteObject (if the user attached such permission) or
// notes that delete failed but Put succeeded (which is the *correct* posture
// for a real production collector key — it should not have delete!).

import { createHash, createHmac } from 'node:crypto';

export function generateIamPolicy({ bucket, kmsKeyArn, accessKeyId }) {
  const arnBase = `arn:aws:s3:::${bucket}`;
  const userPrefix = accessKeyId ? `${accessKeyId}/*` : '${aws:username}/*';
  const stmts = [
    {
      Sid: 'CollectorPutObjectOnly',
      Effect: 'Allow',
      Action: ['s3:PutObject'],
      Resource: `${arnBase}/${userPrefix}`,
      Condition: {
        StringEquals: { 's3:x-amz-server-side-encryption': 'aws:kms' },
        Bool: { 'aws:SecureTransport': 'true' },
        ...(kmsKeyArn ? { 'StringEqualsIfExists': { 's3:x-amz-server-side-encryption-aws-kms-key-id': kmsKeyArn } } : {}),
      },
    },
  ];
  if (kmsKeyArn) {
    stmts.push({
      Sid: 'CollectorKMSEncryptOnly',
      Effect: 'Allow',
      Action: ['kms:GenerateDataKey'],
      Resource: kmsKeyArn,
    });
  }
  return { Version: '2012-10-17', Statement: stmts };
}

export async function validateS3Connection({ bucket, region, accessKeyId, secretAccessKey, endpoint, sseKmsKeyId }) {
  if (!bucket || !region || !accessKeyId || !secretAccessKey) {
    throw new Error('bucket, region, accessKeyId, secretAccessKey all required');
  }
  const host = endpoint
    ? endpoint.replace(/^https?:\/\//, '')
    : `${bucket}.s3.${region}.amazonaws.com`;
  const scheme = endpoint?.startsWith('http://') ? 'http' : 'https';
  const key = `_dfir-validate/${Date.now()}-${Math.random().toString(36).slice(2)}.txt`;

  const headers = {
    'host': host,
  };
  if (sseKmsKeyId) {
    headers['x-amz-server-side-encryption'] = 'aws:kms';
    headers['x-amz-server-side-encryption-aws-kms-key-id'] = sseKmsKeyId;
  }

  const body = Buffer.from('dfir-agentbuilder-validate-ok\n', 'utf8');
  const url = `${scheme}://${host}/${encodeURIComponent(key).replace(/%2F/g, '/')}`;
  const signed = sigV4Sign({
    method: 'PUT',
    url,
    region,
    service: 's3',
    accessKeyId,
    secretAccessKey,
    body,
    headers,
  });

  const resp = await fetch(url, { method: 'PUT', headers: signed.headers, body });
  const text = await resp.text();
  if (!resp.ok) {
    return { ok: false, status: resp.status, error: text.slice(0, 500) };
  }
  return {
    ok: true,
    status: resp.status,
    note: 'PutObject succeeded — collector will be able to upload. (Production collector keys should NOT have DeleteObject; we did not attempt delete.)',
    testKey: key,
  };
}

// ---------------- SigV4 signer (Node-side) ----------------

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function hmac(key, msg) {
  return createHmac('sha256', key).update(msg).digest();
}

function sigV4Sign({ method, url, region, service, accessKeyId, secretAccessKey, body, headers }) {
  const u = new URL(url);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body);

  const finalHeaders = { ...headers, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  const sortedKeys = Object.keys(finalHeaders).map((k) => k.toLowerCase()).sort();
  const canonicalHeaders = sortedKeys.map((k) => `${k}:${finalHeaders[Object.keys(finalHeaders).find((x) => x.toLowerCase() === k)]}\n`).join('');
  const signedHeaders = sortedKeys.join(';');

  const canonicalUri = encodeURI(u.pathname).replace(/%2F/g, '/');
  const canonicalQuery = '';

  const canonicalRequest = [
    method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
  ].join('\n');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, sha256Hex(canonicalRequest)].join('\n');

  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = hmac(kSigning, stringToSign).toString('hex');

  finalHeaders.Authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { headers: finalHeaders };
}
