#!/usr/bin/env python3
"""Cron script to log 2FA codes every minute"""
from pathlib import Path
from datetime import datetime, timezone
import sys

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

from src import crypto


def main():
    # 1. Read hex seed from persistent storage
    seed_file = Path('/data/seed.txt')
    if not seed_file.exists():
        return  # Exit silently if no seed file
    
    try:
        hex_seed = seed_file.read_text().strip()
    except Exception:
        return  # Handle read errors gracefully
    
    # 2. Generate current TOTP code
    try:
        code = crypto.generate_totp_code(hex_seed)
    except Exception:
        return 
    
    # 3. Get current UTC timestamp
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    # 4. Output formatted line 
    print(f"{timestamp} - 2FA Code: {code}")


if __name__ == '__main__':
    main()
