"""
phase3/server.py — Secure AES-GCM server + browser visualizer in one process.

Runs on port 5001.
Open: http://127.0.0.1:5001

Endpoints:
  GET  /              → browser UI
  POST /encrypt       → AES-GCM encrypt
  POST /decrypt       → AES-GCM decrypt (tag verified first)
  GET  /status        → server info
"""

import os, json
from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app        = Flask(__name__)
SECRET_KEY = AESGCM.generate_key(bit_length=256)
gcm        = AESGCM(SECRET_KEY)


# ── Encrypt ───────────────────────────────────────────────────────────────────

@app.route("/encrypt", methods=["POST"])
def encrypt():
    body = request.get_json(silent=True) or {}
    pt   = body.get("plaintext", "").strip()
    if not pt:
        return jsonify({"error": "plaintext required"}), 400

    nonce      = os.urandom(12)                  # 96-bit random nonce
    ct_and_tag = gcm.encrypt(nonce, pt.encode(), None)
    ciphertext = ct_and_tag[:-16]                # everything except last 16 bytes
    tag        = ct_and_tag[-16:]                # last 16 bytes = auth tag

    return jsonify({
        "plaintext":       pt,
        "plaintext_hex":   pt.encode().hex(),
        "plaintext_bytes": len(pt),
        "nonce":           nonce.hex(),
        "nonce_bits":      96,
        "ciphertext":      ciphertext.hex(),
        "ciphertext_bytes": len(ciphertext),
        "tag":             tag.hex(),
        "tag_bits":        128,
        "algorithm":       "AES-256-GCM",
        "key_bits":        256,
    })


# ── Decrypt ───────────────────────────────────────────────────────────────────

@app.route("/decrypt", methods=["POST"])
def decrypt():
    body = request.get_json(silent=True) or {}
    try:
        nonce = bytes.fromhex(body["nonce"])
        ct    = bytes.fromhex(body["ciphertext"])
        tag   = bytes.fromhex(body["tag"])
    except (KeyError, ValueError) as e:
        return jsonify({
            "error":        "Authentication failed",
            "reason":       "Invalid or missing fields",
            "tampered":     True,
            "oracle":       False,
            "step_reached": "input_validation"
        }), 403

    # Step 1: recompute tag and compare BEFORE decrypting
    try:
        plaintext = gcm.decrypt(nonce, ct + tag, None)
        return jsonify({
            "plaintext":       plaintext.decode(),
            "plaintext_hex":   plaintext.hex(),
            "nonce":           nonce.hex(),
            "ciphertext":      ct.hex(),
            "tag":             tag.hex(),
            "tag_verified":    True,
            "tampered":        False,
            "step_reached":    "decryption_complete",
            "algorithm":       "AES-256-GCM",
        })
    except Exception:
        # Always the same generic error — no oracle, no timing difference
        return jsonify({
            "error":        "Authentication failed",
            "reason":       "Auth tag mismatch — ciphertext was modified",
            "tampered":     True,
            "oracle":       False,
            "step_reached": "tag_verification",
            "info":         "Decryption was never attempted"
        }), 403


# ── Status ────────────────────────────────────────────────────────────────────

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "server":    "AES-GCM Secure Server — Phase 3",
        "port":      5001,
        "algorithm": "AES-256-GCM",
        "nonce":     "96-bit random per encryption",
        "tag":       "128-bit GHASH authentication tag",
        "oracle":    False,
        "safe":      True
    })


# ── Browser UI ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("gcm.html")


if __name__ == "__main__":
    print("[*] AES-GCM server + UI running at http://127.0.0.1:5001")
    print("[*] Algorithm : AES-256-GCM")
    print("[*] Key size  : 256-bit (generated at startup)")
    print("[+] Padding oracle attacks are impossible against this server.")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)