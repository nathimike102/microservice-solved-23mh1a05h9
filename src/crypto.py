from typing import Tuple, Union
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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
