from typing import Tuple, Union
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
import base64
import re
import binascii
import time
import hmac
import hashlib

# Make pyotp optional
try:
    import pyotp
except Exception:
    pyotp = None


def generate_rsa_keypair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate RSA key pair

    Returns:
        Tuple of (private_key, public_key) objects

    Implementation:
    - Use the `cryptography` library to generate a 4096-bit RSA key
    - Set public exponent to 65537
    - Serialize to PEM format
    - Return the key objects for further use
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def write_keypair_files(
    repo_root: Union[str, Path] = None,
    private_name: str = "student_private.pem",
    public_name: str = "student_public.pem",
    key_size: int = 4096,
):
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]
    repo_root = Path(repo_root)

    private_path = repo_root / private_name
    public_path = repo_root / public_name

    private_key, public_key = generate_rsa_keypair(key_size=key_size)

    priv_pem = private_key_to_pem(private_key)
    pub_pem = public_key_to_pem(public_key)

    with open(private_path, "wb") as f:
        f.write(priv_pem)
    os.chmod(private_path, stat.S_IRUSR | stat.S_IWUSR)

    with open(public_path, "wb") as f:
        f.write(pub_pem)
    os.chmod(public_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    return private_path, public_path


def request_seed(student_id: str, github_repo_url: str, api_url: str) -> str:
    """
    Request encrypted seed from instructor API
    
    Steps:
    1. Read student public key from PEM file
       - Open and read the public key file
       - Keep the PEM format with BEGIN/END markers
    
    2. Prepare HTTP POST request payload
       - Create JSON with student_id, github_repo_url, public_key
       - Most HTTP libraries handle newlines in JSON automatically
    
    3. Send POST request to instructor API
       - Use your language's HTTP client
       - Set Content-Type: application/json
       - Include timeout handling
    
    4. Parse JSON response
       - Extract 'encrypted_seed' field
       - Handle error responses appropriately
    
    5. Save encrypted seed to file
       - Write to encrypted_seed.txt as plain text
    """
    import json
    import urllib.request
    import urllib.error

    repo_root = Path(__file__).resolve().parents[1]
    pub_path = repo_root / "student_public.pem"
    out_path = repo_root / "encrypted_seed.txt"

    if not pub_path.exists():
        raise FileNotFoundError(f"Public key not found: {pub_path}")

    public_key_payload = pub_path.read_text(encoding="utf-8")

    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_payload,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(api_url, data=data, headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_data = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            obj = json.loads(resp_data.decode(charset))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP error {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e}") from e

    if not isinstance(obj, dict):
        raise RuntimeError("Unexpected response format from instructor API")

    if obj.get("status") != "success":
        raise RuntimeError(f"Instructor API returned error: {obj}")

    encrypted_seed = obj.get("encrypted_seed")
    if not encrypted_seed:
        raise RuntimeError("No 'encrypted_seed' in API response")

    out_path.write_text(encrypted_seed, encoding="utf-8")

    return encrypted_seed


if __name__ == "__main__":
    priv, pub = write_keypair_files()
    print(f"Wrote: {priv}")
    print(f"Wrote: {pub}")


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP
    
    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key: RSA private key object
    
    Returns:
        Decrypted hex seed (64-character string)
    
    Implementation:
    1. Base64 decode the encrypted seed string
    
    2. RSA/OAEP decrypt with SHA-256
       - Padding: OAEP
       - MGF: MGF1(SHA-256)
       - Hash: SHA-256
       - Label: None
    
    3. Decode bytes to UTF-8 string
    
    4. Validate: must be 64-character hex string
       - Check length is 64
       - Check all characters are in '0123456789abcdef'
    
    5. Return hex seed
    """
    if not isinstance(encrypted_seed_b64, str):
        raise TypeError("encrypted_seed_b64 must be a base64 string")

    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError("Invalid base64 for encrypted seed") from e

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise RuntimeError("Decryption failed") from e

    try:
        seed = plaintext.decode("utf-8")
    except Exception as e:
        raise RuntimeError("Decrypted seed is not valid UTF-8") from e

    if not re.fullmatch(r"[0-9a-f]{64}", seed):
        raise ValueError("Decrypted seed is not a 64-character lowercase hex string")

    return seed


def save_seed_to_data(hex_seed: str, data_dir: str = "/data") -> Path:
    """
    Returns the Path to the saved file.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", hex_seed):
        raise ValueError("hex_seed must be a 64-character lowercase hex string")

    data_path = Path(data_dir)
    data_path.mkdir(parents=True, exist_ok=True)
    seed_file = data_path / "seed.txt"
    seed_file.write_text(hex_seed, encoding="utf-8")
    try:
        os.chmod(seed_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

    return seed_file


def _hex_to_base32(hex_seed: str) -> str:
    """Convert 64-character hex seed to base32 string (no padding removed)."""
    if not re.fullmatch(r"[0-9a-f]{64}", hex_seed):
        raise ValueError("hex_seed must be a 64-character lowercase hex string")
    raw = binascii.unhexlify(hex_seed)
    b32 = base64.b32encode(raw).decode("utf-8")
    return b32
    
def _totp_from_raw_key(raw_key: bytes, for_time: int = None, period: int = 30, digits: int = 6) -> str:
    """Generate TOTP code using raw bytes key (HMAC-SHA1) — pure-Python fallback."""
    if for_time is None:
        for_time = int(time.time())
    counter = int(for_time / period)
    counter_bytes = counter.to_bytes(8, "big")
    h = hmac.new(raw_key, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (int.from_bytes(h[offset : offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed
    
    Args:
        hex_seed: 64-character hex string
    
    Returns:
        6-digit TOTP code as string
    
    Implementation:
    1. Convert hex seed to bytes
       - Parse 64-character hex string to bytes
       - Use your language's hex-to-bytes conversion
    
    2. Convert bytes to base32 encoding
       - Encode the bytes using base32 encoding
       - Decode to string (required by most TOTP libraries)
    
    3. Create TOTP object using your language's TOTP library
       - Initialize with base32-encoded seed
       - Use default settings: SHA-1, 30s period, 6 digits
    
    4. Generate current TOTP code
       - Call library method to get current code
       - Returns 6-digit string (e.g., "123456")
    
    5. Return the code
    """
    raw = binascii.unhexlify(hex_seed)
    if pyotp is not None:
        b32 = _hex_to_base32(hex_seed)
        totp = pyotp.TOTP(b32)
        return totp.now()
    else:
        return _totp_from_raw_key(raw)


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance
    
    Args:
        hex_seed: 64-character hex string
        code: 6-digit code to verify
        valid_window: Number of periods before/after to accept (default 1 = ±30s)
    
    Returns:
        True if code is valid, False otherwise
    
    Implementation:
    1. Convert hex seed to base32 (same process as generation)
    
    2. Create TOTP object with base32 seed
    
    3. Verify code with time window tolerance
       - Use valid_window parameter (default 1 = ±30 seconds)
       - This accounts for clock skew and network delay
       - Library checks current period ± valid_window periods
    
    4. Return verification result
    """
    if not re.fullmatch(r"\d{6}", code):
        raise ValueError("code must be a 6-digit string")
    raw = binascii.unhexlify(hex_seed)
    if pyotp is not None:
        b32 = _hex_to_base32(hex_seed)
        totp = pyotp.TOTP(b32)
        return totp.verify(code, valid_window=valid_window)
    else:
        now = int(time.time())
        period = 30
        for offset in range(-valid_window, valid_window + 1):
            t = now + offset * period
            expected = _totp_from_raw_key(raw, for_time=t)
            if hmac.compare_digest(expected, code):
                return True
        return False
