"""
server.py — Vulnerable AES-CBC Flask server (Phase 1).
Updated: debug endpoints expose every internal step for visualization.
Fixed: /status route added so Phase 4 dashboard can detect this server.

Endpoints:
  GET  /status         →  server info (used by Phase 4 dashboard)
  POST /encrypt        →  standard encrypt
  POST /decrypt        →  standard decrypt (oracle)
  POST /encrypt-debug  →  encrypt + return every internal step
  POST /decrypt-debug  →  decrypt + return every internal step + oracle signal
  GET  /               →  interactive UI
"""

import os, binascii
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from Crypto.Cipher import AES
from crypto_utils import cbc_encrypt, cbc_decrypt, pkcs7_pad, pkcs7_unpad, PaddingError

load_dotenv()
app = Flask(__name__)

_raw_key   = os.getenv("CBC_SECRET_KEY", "0123456789abcdef0123456789abcdef")
SECRET_KEY = bytes.fromhex(_raw_key)[:16]
BLOCK_SIZE = 16


def _bad(msg, code):
    return jsonify({"error": msg}), code

def bytes_to_hex_list(b: bytes) -> list:
    return [f"{x:02x}" for x in b]

def bytes_to_int_list(b: bytes) -> list:
    return list(b)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ── Status (used by Phase 4 dashboard) ───────────────────────────────────────

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "server":      "AES-CBC Vulnerable Server — Phase 1",
        "port":        5000,
        "algorithm":   "AES-128-CBC",
        "padding":     "PKCS#7",
        "oracle":      True,
        "vulnerable":  True,
        "endpoints":   ["/encrypt", "/decrypt", "/encrypt-debug", "/decrypt-debug"]
    })


# ── Standard endpoints ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    body = request.get_json(silent=True)
    if not body or "plaintext" not in body:
        return _bad("Missing 'plaintext' field", 400)
    iv, ct = cbc_encrypt(body["plaintext"].encode(), SECRET_KEY)
    return jsonify({"iv": iv.hex(), "ciphertext": ct.hex()})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    body = request.get_json(silent=True)
    if not body or "iv" not in body or "ciphertext" not in body:
        return _bad("Missing fields", 400)
    try:
        iv = bytes.fromhex(body["iv"])
        ct = bytes.fromhex(body["ciphertext"])
    except (ValueError, binascii.Error):
        return _bad("Invalid hex", 400)
    if len(iv) != 16:
        return _bad("IV must be 16 bytes", 400)
    try:
        pt = cbc_decrypt(ct, iv, SECRET_KEY)
        return jsonify({"status": "ok", "plaintext": pt.decode(errors="replace")})
    except PaddingError as e:
        return jsonify({"status": "padding_error", "detail": str(e)}), 403


# ── Debug encrypt ─────────────────────────────────────────────────────────────

@app.route("/encrypt-debug", methods=["POST"])
def encrypt_debug():
    body = request.get_json(silent=True)
    if not body or "plaintext" not in body:
        return _bad("Missing 'plaintext' field", 400)

    plaintext = body["plaintext"].encode()
    iv        = os.urandom(BLOCK_SIZE)
    padded    = pkcs7_pad(plaintext)
    blocks    = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]

    steps  = []
    prev   = iv
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    ct_blocks = []

    for i, block in enumerate(blocks):
        xor_input = xor_bytes(block, prev)
        ct_block  = cipher.encrypt(bytes(xor_input))
        ct_blocks.append(ct_block)
        steps.append({
            "block_num":       i,
            "plaintext_block": bytes_to_hex_list(block),
            "prev_block":      bytes_to_hex_list(prev),
            "xor_result":      bytes_to_hex_list(xor_input),
            "ct_block":        bytes_to_hex_list(ct_block),
            "plaintext_ascii": [chr(b) if 32 <= b < 127 else "." for b in block],
            "is_padding":      [
                (b == (BLOCK_SIZE - len(plaintext) % BLOCK_SIZE or BLOCK_SIZE))
                and (i == len(blocks) - 1)
                for b in block
            ],
            "pad_bytes_count": (BLOCK_SIZE - len(plaintext) % BLOCK_SIZE or BLOCK_SIZE)
                                if i == len(blocks)-1 else 0,
        })
        prev = ct_block

    ciphertext = b"".join(ct_blocks)

    return jsonify({
        "original_plaintext": body["plaintext"],
        "plaintext_bytes":    bytes_to_hex_list(plaintext),
        "plaintext_length":   len(plaintext),
        "pad_length":         BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE) or BLOCK_SIZE,
        "padded_bytes":       bytes_to_hex_list(padded),
        "padded_length":      len(padded),
        "num_blocks":         len(blocks),
        "iv":                 bytes_to_hex_list(iv),
        "key_preview":        bytes_to_hex_list(SECRET_KEY[:4]) + ["??"] * 12,
        "blocks":             steps,
        "ciphertext":         ciphertext.hex(),
        "iv_hex":             iv.hex(),
    })


# ── Debug decrypt ─────────────────────────────────────────────────────────────

@app.route("/decrypt-debug", methods=["POST"])
def decrypt_debug():
    body = request.get_json(silent=True)
    if not body or "iv" not in body or "ciphertext" not in body:
        return _bad("Missing fields", 400)

    try:
        iv = bytes.fromhex(body["iv"])
        ct = bytes.fromhex(body["ciphertext"])
    except (ValueError, binascii.Error):
        return _bad("Invalid hex encoding", 400)

    if len(iv) != 16:
        return _bad("IV must be 16 bytes", 400)
    if len(ct) % BLOCK_SIZE != 0:
        return _bad("Ciphertext not multiple of 16", 400)

    ct_blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    cipher    = AES.new(SECRET_KEY, AES.MODE_ECB)
    steps     = []
    prev      = iv

    for i, ct_block in enumerate(ct_blocks):
        aes_out  = cipher.decrypt(bytes(ct_block))
        pt_block = xor_bytes(aes_out, prev)
        steps.append({
            "block_num":      i,
            "ct_block":       bytes_to_hex_list(ct_block),
            "aes_raw_output": bytes_to_hex_list(aes_out),
            "prev_block":     bytes_to_hex_list(prev),
            "pt_block":       bytes_to_hex_list(pt_block),
            "pt_ascii":       [chr(b) if 32 <= b < 127 else "." for b in pt_block],
        })
        prev = ct_block

    last_block  = steps[-1]["pt_block"]
    last_bytes  = [int(h, 16) for h in last_block]
    pad_val     = last_bytes[-1]
    pad_valid   = (1 <= pad_val <= BLOCK_SIZE and
                   all(b == pad_val for b in last_bytes[-pad_val:]))

    padding_map = [False] * BLOCK_SIZE
    if pad_valid:
        for k in range(pad_val):
            padding_map[BLOCK_SIZE - 1 - k] = True

    recovered_pt = None
    if pad_valid:
        all_pt = b"".join(
            bytes(int(h, 16) for h in s["pt_block"]) for s in steps
        )
        try:
            recovered_pt = pkcs7_unpad(all_pt).decode(errors="replace")
        except PaddingError:
            pad_valid = False

    return jsonify({
        "iv":                  bytes_to_hex_list(iv),
        "num_blocks":          len(ct_blocks),
        "blocks":              steps,
        "last_block_bytes":    last_bytes,
        "pad_val":             pad_val,
        "pad_valid":           pad_valid,
        "padding_map":         padding_map,
        "oracle_signal":       "HTTP 200 — VALID padding" if pad_valid
                               else "HTTP 403 — INVALID padding  ← oracle leak",
        "oracle_code":         200 if pad_valid else 403,
        "recovered_plaintext": recovered_pt,
    }), (200 if pad_valid else 403)


if __name__ == "__main__":
    print("[*] Vulnerable CBC server running at http://127.0.0.1:5000")
    print("[!] WARNING: This server intentionally leaks padding errors.")
    app.run(host="0.0.0.0", port=5000, debug=False)