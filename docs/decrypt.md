# Decrypting a collected container

Each `Collector_<id>.exe` produces a `.zip.enc` container in S3 (or local). To decrypt, you need the **private RSA key** that was downloaded during the build (Step 4 of the wizard).

## Container layout

```
+----------------+----------+----------------+--------------------+--------------------+
| magic "DFIR"   | ver (1B) | hdr_len (4B BE)| header_json (N B)  | AES-GCM body       |
+----------------+----------+----------------+--------------------+--------------------+
```

`header_json` looks like:

```json
{
  "version": 1,
  "scheme": "rsa-oaep-sha256+aes-256-gcm",
  "build_id": "a3f9b221-...",
  "created_at": "2026-05-06T14:30:00Z",
  "wrapped_key_b64": "<RSA-OAEP-SHA256-wrapped 32-byte AES key>",
  "nonce_b64": "<12-byte GCM nonce>",
  "key_fingerprint_sha256": "<hex SHA256 of the public key DER>"
}
```

The header is **AAD-bound** — any tampering invalidates the authentication tag.

## Python decryption helper

Save as `decrypt.py`. Requires `pip install cryptography`.

```python
#!/usr/bin/env python3
"""DFIR collector container decryptor."""
import argparse, base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt(enc_path: str, key_path: str, out_path: str):
    with open(enc_path, "rb") as f:
        magic = f.read(4)
        if magic != b"DFIR":
            sys.exit(f"Bad magic: {magic!r}")
        version = f.read(1)[0]
        if version != 1:
            sys.exit(f"Unsupported version: {version}")
        hdr_len = struct.unpack(">I", f.read(4))[0]
        hdr_json = f.read(hdr_len)
        body = f.read()
        hdr = json.loads(hdr_json)

    with open(key_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)

    # Optional: verify fingerprint matches
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = hashlib.sha256(pub_der).hexdigest()
    if fp != hdr["key_fingerprint_sha256"]:
        sys.exit(f"Private key fingerprint mismatch:\n  expect: {hdr['key_fingerprint_sha256']}\n  actual: {fp}")

    wrapped = base64.b64decode(hdr["wrapped_key_b64"])
    nonce   = base64.b64decode(hdr["nonce_b64"])

    aes_key = priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    cipher = AESGCM(aes_key)
    plaintext = cipher.decrypt(nonce, body, hdr_json)

    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted -> {out_path} ({len(plaintext)} bytes)")
    print(f"Build ID: {hdr['build_id']}")
    print(f"Created:  {hdr['created_at']}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", required=True, help="The .zip.enc container")
    ap.add_argument("--key",   "-k", required=True, help="The PEM private key from the wizard")
    ap.add_argument("--output","-o", required=True, help="Output .zip path")
    args = ap.parse_args()
    decrypt(args.input, args.key, args.output)
```

Usage:

```bash
# Pull the container from S3
aws s3 cp s3://ir-evidence-acmecorp-2026/APAC-HYD/LAPTOP-A1B2C3/2026-05-06T14-30-00Z_collection.zip.enc .

# Pull the private key from Secrets Manager
aws secretsmanager get-secret-value \
    --secret-id dfir/build-a3f9b221/privkey \
    --query SecretString --output text > privkey.pem

# Decrypt
python decrypt.py -i 2026-05-06T14-30-00Z_collection.zip.enc \
                  -k privkey.pem \
                  -o collection.zip

# Then unzip and analyze
unzip collection.zip -d evidence/
```

## Verifying chain of custody

Each container's header includes:
- The build ID (cross-reference against the audit ledger).
- The collection timestamp (compare to endpoint's reported clock).
- The public key fingerprint (proves which build produced this).

Combined with S3 Object Lock + bucket versioning, this gives a tamper-evident chain: any modification to the encrypted container after upload would either break the GCM auth tag or be blocked by Object Lock.

## Troubleshooting

**"Private key fingerprint mismatch"** — You're using a private key from a different build. Look up the build_id in the header and find the matching private key in Secrets Manager.

**"AES-GCM authentication failed"** — The container has been tampered with, OR the file is truncated (incomplete S3 multipart upload). Check the S3 object's ETag and size against the audit ledger.
