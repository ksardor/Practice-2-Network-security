#!/usr/bin/env python3
"""
brute_force_gpg.py

Brute-force lowercase-only passphrases for a symmetric GPG-encrypted file.

Usage:
    python3 brute_force_gpg.py --file archive.pdf.gpg --min 1 --max 5 --workers 8

Requirements:
    - Python 3.8+
    - gpg installed and in PATH
"""

import argparse
import itertools
import multiprocessing as mp
import os
import subprocess
import string
import sys
import time
import json

ALPHABET = string.ascii_lowercase  # 'abcdefghijklmnopqrstuvwxyz'
CHECKPOINT_FILE = "bf_checkpoint.json"
FOUND_FILE = "found.txt"

def gpg_try_decrypt(gpg_file, passphrase, timeout=15):
    """Attempt to decrypt using gpg. Return True and output path if successful."""
    import tempfile
    out = tempfile.NamedTemporaryFile(delete=False)
    out.close()
    cmd = [
        "gpg", "--batch", "--yes",
        "--passphrase", passphrase,
        "-o", out.name, "-d", gpg_file
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except Exception as e:
        try:
            os.unlink(out.name)
        except:
            pass
        return False, f"ERROR: {e}"

    if res.returncode == 0:
        # Validate output (PDF starts with %PDF)
        try:
            with open(out.name, "rb") as f:
                head = f.read(4)
            valid = head == b"%PDF"
        except Exception:
            valid = True  # accept even if we can't read
        if valid:
            return True, out.name
        else:
            # not a PDF but gpg returned 0: still consider success
            return True, out.name
    else:
        try:
            os.unlink(out.name)
        except:
            pass
        return False, res.stderr.decode(errors="replace")[:200]

def worker_task(args):
    """Worker receives a tuple (gpg_file, candidate) and tries it."""
    gpg_file, candidate = args
    ok, info = gpg_try_decrypt(gpg_file, candidate)
    return (candidate, ok, info)

def generate_candidates(min_len, max_len, alphabet):
    """Yield passphrase candidates (strings) in increasing length order."""
    for length in range(min_len, max_len+1):
        for tup in itertools.product(alphabet, repeat=length):
            yield "".join(tup)

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r") as f:
                return json.load(f)
        except:
            return None
    return None

def save_checkpoint(pos_info):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(pos_info, f)

def main():
    parser = argparse.ArgumentParser(description="Brute-force lowercase GPG passphrase (symmetric).")
    parser.add_argument("--file", required=True, help="Path to .gpg file")
    parser.add_argument("--min", type=int, default=1, help="Minimum passphrase length")
    parser.add_argument("--max", type=int, default=5, help="Maximum passphrase length")
    parser.add_argument("--workers", type=int, default=max(1, mp.cpu_count()-1), help="Number of worker processes")
    parser.add_argument("--chunk", type=int, default=5000, help="How many candidates to dispatch per batch")
    parser.add_argument("--alphabet", default=ALPHABET, help="Characters to use (default: lowercase)")
    parser.add_argument("--timeout", type=int, default=15, help="gpg call timeout in seconds")
    args = parser.parse_args()

    gpg_file = args.file
    if not os.path.exists(gpg_file):
        print("File not found:", gpg_file)
        sys.exit(1)

    # Load checkpoint to resume
    ck = load_checkpoint()
    start_len = args.min
    start_index = 0
    if ck:
        if ck.get("file") == gpg_file:
            start_len = ck.get("length", args.min)
            start_index = ck.get("index", 0)
            print(f"Resuming from length={start_len}, index={start_index}")
        else:
            print("Checkpoint file exists but is for a different target file. Ignoring checkpoint.")

    pool = mp.Pool(processes=args.workers)
    try:
        total_tested = 0
        found = None
        for length in range(start_len, args.max + 1):
            # Create iterator over candidates at this length
            # If resuming within this length, skip first start_index combos
            combos = itertools.product(args.alphabet, repeat=length)
            idx = 0
            # fast-skip to start_index if resuming
            if length == start_len and start_index:
                # Consume first start_index combos
                for _ in range(start_index):
                    next(combos, None)
                idx = start_index

            batch = []
            for c in combos:
                candidate = "".join(c)
                batch.append((gpg_file, candidate))
                if len(batch) >= args.chunk:
                    # dispatch batch
                    results = pool.map(worker_task, batch)
                    for candidate, ok, info in results:
                        total_tested += 1
                        idx += 1
                        if ok:
                            found = (candidate, info)
                            break
                    # checkpoint progress
                    save_checkpoint({"file": gpg_file, "length": length, "index": idx})
                    batch = []
                    if found:
                        break
            # leftover batch
            if not found and batch:
                results = pool.map(worker_task, batch)
                for candidate, ok, info in results:
                    total_tested += 1
                    idx += 1
                    if ok:
                        found = (candidate, info)
                        break
                save_checkpoint({"file": gpg_file, "length": length, "index": idx})

            if found:
                break

        if found:
            pw, outpath = found
            print("=== PASSFOUND ===")
            print("Passphrase:", pw)
            print("Decrypted output at:", outpath)
            with open(FOUND_FILE, "w") as f:
                f.write(pw + "\n")
            # remove checkpoint
            try:
                os.remove(CHECKPOINT_FILE)
            except:
                pass
        else:
            print("No passphrase found in the given range.")
            print("Total candidates tested:", total_tested)
    finally:
        pool.close()
        pool.join()

if __name__ == "__main__":
    main()

