#!/usr/bin/env python3
"""Cron helper: generate current TOTP and write to /cron/last_code.txt"""
from pathlib import Path
import sys

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

from src import crypto


def main():
    seed_file = Path('/data/seed.txt')
    if not seed_file.exists():
        return
    hex_seed = seed_file.read_text().strip()
    try:
        code = crypto.generate_totp_code(hex_seed)
    except Exception:
        return
    out_dir = Path('/cron')
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / 'last_code.txt'
    out.write_text(code, encoding='utf-8')


if __name__ == '__main__':
    main()
