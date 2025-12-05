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


if __name__ == "__main__":
    priv, pub = write_keypair_files()
    print(f"Wrote: {priv}")
    print(f"Wrote: {pub}")
