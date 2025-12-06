# PKI 2FA Microservice

A secure microservice implementing two-factor authentication (2FA) using TOTP (Time-based One-Time Password) with RSA encryption for key distribution.

## Overview

This project demonstrates:

- **RSA Cryptography**: Key generation, encryption/decryption (OAEP), and signing (PSS)
- **TOTP Implementation**: Standards-compliant 2FA code generation and verification
- **Docker Containerization**: Multi-stage build with cron job automation
- **API Design**: FastAPI endpoints for seed decryption and 2FA operations

## Features

### Security

- **RSA-4096**: Asymmetric encryption for seed distribution
- **RSA-PSS-SHA256**: Secure commit signing
- **RSA-OAEP-SHA256**: Confidential seed encryption
- **TOTP-SHA1**: Industry-standard 2FA implementation

### Automation

- **Cron Job**: Generates and logs TOTP codes every minute
- **Docker Compose**: Simplified deployment with volume persistence
- **Multi-stage Build**: Optimized image size with build/runtime separation

### Architecture

```
Student                Instructor API              Evaluator
   |                        |                          |
   +---> Request Seed ------>|                          |
   |     (with public key)    |                          |
   |                          +---- Generate Seed ---+   |
   |                          |                      |   |
   |<----- Encrypted Seed ----+                      |   |
   |                                                 |   |
   +-----------> Decrypt (private key)              |   |
   |                                                 |   |
   | (Seed stored in /data/seed.txt)                |   |
   |                                                 |   |
   +-------> Cron: Generate TOTP every minute      |   |
   |                                                 |   |
   +-------> API: /generate-2fa, /verify-2fa       |   |
   |                                                 |   |
   +-------> Generate Commit Proof                 |   |
   |     (sign + encrypt commit hash)              |   |
   |                                                 |   |
   +----------- Submit Proof + Keys ----------------->|
                                                       |
                                    Verify signature
                                    Decrypt seed
                                    Check TOTP/cron
                                    Evaluate
```

## Project Structure

```
.
├── src/
│   ├── __init__.py
│   ├── crypto.py          # RSA, TOTP, signing, encryption
│   └── api.py             # FastAPI endpoints
├── scripts/
│   ├── generate_commit_proof.py   # Create signed commit proof
│   ├── log_2fa_cron.py            # Cron script to log TOTP codes
│   └── totp_cron (deprecated)
├── cron/
│   └── 2fa-cron           # Cron job configuration (LF endings)
├── Dockerfile             # Multi-stage Docker build
├── docker-compose.yml     # Service configuration
├── requirements.txt       # Python dependencies
├── .gitattributes         # Enforce LF line endings for cron file
├── .gitignore             # Exclude sensitive files
├── student_private.pem    # Private key (for decryption)
├── student_public.pem     # Public key (for encryption)
├── instructor_public.pem  # Instructor's public key (for proof)
├── encrypted_seed.txt     # Encrypted TOTP seed
└── README.md              # This file
```

## Setup & Usage

### Prerequisites

- Docker and Docker Compose (or Python 3.11+)
- Git (for commit hash generation)

### Quick Start

#### Using Docker (Recommended)

```bash
# Build and start
docker build -t microservice:latest .
docker run -d --name microservice_app \
  -p 8080:8080 \
  -v seed-data:/data \
  -v cron-output:/cron \
  -v "$PWD/student_private.pem:/app/student_private.pem:ro" \
  -v "$PWD/student_public.pem:/app/student_public.pem:ro" \
  -v "$PWD/instructor_public.pem:/app/instructor_public.pem:ro" \
  -e TZ=UTC \
  microservice:latest

# Test API
curl http://localhost:8080/generate-2fa
```

Or use docker-compose:

```bash
docker compose up -d
```

#### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run API server
uvicorn src.api:app --reload --host 0.0.0.0 --port 8080
```

## API Endpoints

### POST `/decrypt-seed`

Decrypt the encrypted seed and save to persistent storage.

**Request:**

```json
{
  "encrypted_seed": "base64-encoded-ciphertext"
}
```

**Response:**

```json
{
  "status": "ok"
}
```

### GET `/generate-2fa`

Generate current TOTP code with validity window.

**Response:**

```json
{
  "code": "123456",
  "valid_for": 25
}
```

### POST `/verify-2fa`

Verify a TOTP code with time-window tolerance (±30 seconds).

**Request:**

```json
{
  "code": "123456"
}
```

**Response:**

```json
{
  "valid": true
}
```

## Cryptography Implementation

### Key Generation (RSA-4096)

```python
from src.crypto import generate_rsa_keypair, write_keypair_files

# Generate and save keys
priv_path, pub_path = write_keypair_files()
```

### Seed Decryption (RSA-OAEP-SHA256)

```python
from src.crypto import decrypt_seed

# Decrypt encrypted seed
hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
# Returns: 64-character hex string
```

### TOTP Code Generation (HMAC-SHA1, 30s periods)

```python
from src.crypto import generate_totp_code, verify_totp_code

# Generate current code
code = generate_totp_code(hex_seed)  # Returns: "123456"

# Verify code with ±30s tolerance
valid = verify_totp_code(hex_seed, "123456", valid_window=1)
```

### Commit Signing (RSA-PSS-SHA256)

```python
from src.crypto import sign_message, encrypt_with_public_key

# Sign commit hash
signature = sign_message(commit_hash, student_private_key)

# Encrypt signature
encrypted = encrypt_with_public_key(signature, instructor_public_key)

# Base64 encode
proof = base64.b64encode(encrypted).decode('ascii')
```

## Cron Job Configuration

The cron job runs every minute and logs TOTP codes to `/cron/last_code.txt`:

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/install/bin
PYTHONPATH=/install/lib/python3.11/site-packages

* * * * * root cd /app && /usr/local/bin/python3 scripts/log_2fa_cron.py >> /cron/last_code.txt 2>&1
```

**Output format:**

```
2025-12-06 03:48:01 - 2FA Code: 914918
2025-12-06 03:49:01 - 2FA Code: 955622
```

## Docker Configuration

### Multi-stage Build

- **Stage 1 (Builder)**: Installs build dependencies, builds wheels
- **Stage 2 (Runtime)**: Minimal Python image with cron, tzdata, and app code

### Volumes

- `seed-data:/data` - Persistent seed storage
- `cron-output:/cron` - Cron output logs
- Key files mounted read-only

### Environment

- `TZ=UTC` - Ensure UTC timezone for TOTP consistency

## Testing

### Verify Installation

```bash
# Check container status
docker ps -a --filter name=microservice_app

# View logs
docker logs microservice_app

# Test endpoints
curl http://localhost:8080/generate-2fa
curl -X POST http://localhost:8080/verify-2fa \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

### Check Cron Output

```bash
# Wait 70+ seconds for cron to run
sleep 70

# View logged codes
docker exec microservice_app cat /cron/last_code.txt
```

### Generate Commit Proof

```bash
python3 scripts/generate_commit_proof.py
```

## Security Notes

⚠️ **Public Keys in Repository**

The key files (`student_private.pem`, `student_public.pem`, `instructor_public.pem`) are included in this repository for educational purposes only.

**These keys are PUBLIC in GitHub and should NOT be reused for any production use.**

## Dependencies

- **cryptography**: RSA, OAEP, PSS, TOTP
- **FastAPI**: Web API framework
- **Uvicorn**: ASGI application server
- **pyotp**: Optional TOTP fallback (pure Python implementation included)
- **Pydantic**: Request validation

See `requirements.txt` for versions.

## Common Mistakes Avoided

This implementation properly handles:

- ✅ RSA-PSS signing (not PKCS#1 v1.5)
- ✅ RSA-OAEP decryption (not ECB)
- ✅ Hex-to-base32 seed conversion for TOTP
- ✅ TOTP time-window tolerance (±30s)
- ✅ LF line endings for cron file (not CRLF)
- ✅ UTC timezone for all timestamps
- ✅ Signed ASCII commit hash (not binary)
- ✅ Persistent seed storage in Docker volumes
- ✅ Proper error handling and HTTP status codes
- ✅ Repository URL consistency for API calls

## References

- [RFC 6238: TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 3447: PKCS #1 (RSA)](https://tools.ietf.org/html/rfc3447)
- [cryptography.io Documentation](https://cryptography.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

## Support

For issues or questions, check:

1. Docker container logs: `docker logs microservice_app`
2. Cron logs: `docker exec microservice_app tail -n 50 /var/log/cron.log`
3. Seed file: `docker exec microservice_app cat /data/seed.txt`
4. API health: `curl http://localhost:8080/docs`
