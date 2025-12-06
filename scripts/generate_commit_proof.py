#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path
import base64

# Add repo root to path
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

from src import crypto
from cryptography.hazmat.primitives import serialization


def get_commit_hash() -> str:
    """Get the current commit hash"""
    result = subprocess.run(
        ['git', 'log', '-1', '--format=%H'],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()


def load_private_key(key_path: Path):
    """Load RSA private key from PEM file"""
    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return private_key


def load_public_key(key_path: Path):
    """Load RSA public key from PEM file"""
    with open(key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key


def main():
    # 1. Get current commit hash
    commit_hash = get_commit_hash()
    print(f"Commit Hash: {commit_hash}")
    
    # 2. Load student private key
    student_private_path = repo_root / 'student_private.pem'
    student_private_key = load_private_key(student_private_path)
    
    # 3. Sign commit hash with student private key
    signature = crypto.sign_message(commit_hash, student_private_key)
    
    # 4. Load instructor public key
    instructor_public_path = repo_root / 'instructor_public.pem'
    instructor_public_key = load_public_key(instructor_public_path)
    
    # 5. Encrypt signature with instructor public key
    encrypted_signature = crypto.encrypt_with_public_key(signature, instructor_public_key)
    
    # 6. Base64 encode encrypted signature
    encoded_signature = base64.b64encode(encrypted_signature).decode('ascii')
    
    print(f"Encrypted Signature: {encoded_signature}")
    
    return commit_hash, encoded_signature


if __name__ == '__main__':
    main()
