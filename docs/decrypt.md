# Decrypting a collected container

Each `Collector_<id>.exe` produces a `.zip.enc` container in S3 (or local). To decrypt, you need the **private RSA key** that was downloaded during the build (Step 4 of the wizard).

## Container layout

The current format is **version 2 (chunked)**. The bulk data is encrypted in
independent AES-256-GCM chunks so a multi-GB forensic ZIP encrypts and decrypts
in constant memory — it is never loaded whole into RAM.

```
+--------------+----------+-----------------+-------------------+
| magic "DFIR" | ver (1B) | hdr_len (4B BE) | header_json (N B) |
+--------------+----------+-----------------+-------------------+
then repeated until EOF, one record per chunk:
+---------------------+----------------------------+
| chunk_len (4B BE u32)| chunk ciphertext + 16B tag |
+---------------------+----------------------------+
```

`header_json` looks like:

```json
{
  "version": 2,
  "scheme": "rsa-oaep-sha256+aes-256-gcm-chunked",
  "build_id": "a3f9b221-...",
  "created_at": "2026-05-06T14:30:00Z",
  "wrapped_key_b64": "<RSA-OAEP-SHA256-wrapped 32-byte AES key>",
  "nonce_b64": "<8-byte nonce base (v2) | 12-byte nonce (legacy v1)>",
  "key_fingerprint_sha256": "<hex SHA256 of the public key DER>"
}
```

For each chunk `i` (0-based):
- **nonce** = `nonce_base` (8 bytes) ‖ `i` as 4-byte big-endian → 12-byte GCM nonce.
- **AAD** = `header_json` bytes ‖ `i` as 4-byte big-endian ‖ a 1-byte
  `is_last` flag (`0x01` for the final chunk, else `0x00`).

Binding the index and last-flag into the AAD makes reordering, dropping, or
truncating chunks fail authentication — so a partial/truncated upload cannot be
silently decrypted as if it were complete.

The helper below also decrypts **legacy version 1** containers (single-shot
whole-body GCM with a 12-byte nonce and the header bytes as AAD) for any
evidence built before the chunked format.

## Python decryption helper

Save as `decrypt.py`. Requires `pip install cryptography`. It streams chunk by
chunk, so it handles containers far larger than RAM.

```python
#!/usr/bin/env python3
"""DFIR collector container decryptor (supports v2 chunked + legacy v1)."""
import argparse, base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _unwrap_key(hdr, key_path):
    with open(key_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = hashlib.sha256(pub_der).hexdigest()
    if fp != hdr["key_fingerprint_sha256"]:
        sys.exit(f"Private key fingerprint mismatch:\n  expect: {hdr['key_fingerprint_sha256']}\n  actual: {fp}")
    return priv.decrypt(
        base64.b64decode(hdr["wrapped_key_b64"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

def decrypt(enc_path: str, key_path: str, out_path: str):
    with open(enc_path, "rb") as f:
        if f.read(4) != b"DFIR":
            sys.exit("Bad magic (not a DFIR container)")
        version = f.read(1)[0]
        hdr_len = struct.unpack(">I", f.read(4))[0]
        hdr_json = f.read(hdr_len)
        hdr = json.loads(hdr_json)
        aes_key = _unwrap_key(hdr, key_path)
        cipher = AESGCM(aes_key)
        nonce_field = base64.b64decode(hdr["nonce_b64"])
        total = 0

        if version == 1:
            # Legacy single-shot: 12-byte nonce, whole body, AAD = header bytes.
            body = f.read()
            pt = cipher.decrypt(nonce_field, body, hdr_json)
            with open(out_path, "wb") as out:
                out.write(pt)
            total = len(pt)
        elif version == 2:
            if len(nonce_field) != 8:
                sys.exit(f"v2 nonce base must be 8 bytes, got {len(nonce_field)}")
            def read_record():
                lb = f.read(4)
                if not lb:
                    return None              # clean EOF at a chunk boundary
                if len(lb) != 4:
                    sys.exit("truncated chunk length")
                (ln,) = struct.unpack(">I", lb)
                ct = f.read(ln)
                if len(ct) != ln:
                    sys.exit("truncated chunk body")
                return ct
            with open(out_path, "wb") as out:
                idx = 0
                cur = read_record()
                if cur is None:
                    sys.exit("container has no chunks")
                while True:
                    nxt = read_record()
                    is_last = nxt is None
                    nonce = nonce_field + struct.pack(">I", idx)
                    aad = hdr_json + struct.pack(">I", idx) + bytes([1 if is_last else 0])
                    pt = cipher.decrypt(nonce, cur, aad)  # raises on tamper/truncation
                    out.write(pt)
                    total += len(pt)
                    idx += 1
                    if is_last:
                        break
                    cur = nxt
        else:
            sys.exit(f"Unsupported container version: {version}")

    print(f"Decrypted -> {out_path} ({total} bytes)")
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
