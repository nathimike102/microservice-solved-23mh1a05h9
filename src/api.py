from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import time
import json

from cryptography.hazmat.primitives import serialization

from . import crypto

app = FastAPI()

class EncryptedSeedRequest(BaseModel):
    encrypted_seed: str

class VerifyCodeRequest(BaseModel):
    code: str

def _load_private_key(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(req: EncryptedSeedRequest):
    repo_root = Path(__file__).resolve().parents[1]
    priv_path = repo_root / "student_private.pem"
    try:
        private_key = _load_private_key(priv_path)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})
    try:
        seed = crypto.decrypt_seed(req.encrypted_seed, private_key)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})
    try:
        crypto.save_seed_to_data(seed, data_dir="/data")
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})
    return {"status": "ok"}

@app.get("/generate-2fa")
def generate_2fa():
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [Path.cwd() / "data" / "seed.txt", repo_root / "data" / "seed.txt", Path("/data/seed.txt")]
    seed_file = next((p for p in candidates if p.exists()), None)
    if seed_file is None:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    hex_seed = seed_file.read_text(encoding="utf-8").strip()
    try:
        code = crypto.generate_totp_code(hex_seed)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    period = 30
    valid_for = period - (int(time.time()) % period)
    return {"code": code, "valid_for": valid_for}

@app.post("/verify-2fa")
def verify_2fa(req: VerifyCodeRequest):
    code = (req.code or "").strip()
    if not code or not code.isdigit() or len(code) != 6:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    repo_root = Path(__file__).resolve().parents[1]
    candidates = [repo_root / "data" / "seed.txt", Path("/data/seed.txt")]
    seed_file = next((p for p in candidates if p.exists()), None)
    if seed_file is None:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    hex_seed = seed_file.read_text(encoding="utf-8").strip()
    try:
        valid = crypto.verify_totp_code(hex_seed, code, valid_window=1)
    except ValueError:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    return {"valid": bool(valid)}