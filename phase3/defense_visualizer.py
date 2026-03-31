"""
phase3/defense_visualizer.py — Browser UI for the AES-GCM defense.
Runs on port 5003. Requires phase3/server.py on port 5001.

Run:
    cd phase3
    python defense_visualizer.py
Then open: http://127.0.0.1:5003
"""

import json, time, requests
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

app     = Flask(__name__)
GCM_URL = "http://127.0.0.1:5001"
CBC_URL = "http://127.0.0.1:5000"


# ── Proxy: GCM encrypt ────────────────────────────────────────────────────────

@app.route("/proxy/gcm/encrypt", methods=["POST"])
def proxy_gcm_encrypt():
    body = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{GCM_URL}/encrypt", json=body, timeout=5)
        return jsonify(r.json()), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "GCM server not reachable on port 5001"}), 503


# ── Proxy: GCM decrypt ────────────────────────────────────────────────────────

@app.route("/proxy/gcm/decrypt", methods=["POST"])
def proxy_gcm_decrypt():
    body = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{GCM_URL}/decrypt", json=body, timeout=5)
        return jsonify(r.json()), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "GCM server not reachable on port 5001"}), 503


# ── Proxy: GCM status ─────────────────────────────────────────────────────────

@app.route("/proxy/gcm/status", methods=["GET"])
def proxy_gcm_status():
    try:
        r = requests.get(f"{GCM_URL}/status", timeout=5)
        return jsonify(r.json()), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "GCM server not reachable on port 5001"}), 503


# ── Attack simulation: try padding oracle on GCM ──────────────────────────────

@app.route("/probe/gcm", methods=["POST"])
def probe_gcm():
    """
    Simulate the padding oracle attack against the GCM server.
    Sends 256 tampered requests (like the real attack does per byte)
    and streams the results to show the oracle is silent.
    """
    body = request.get_json(silent=True) or {}
    ct   = body.get("ciphertext", "")
    tag  = body.get("tag", "")

    if not ct or not tag:
        return jsonify({"error": "ciphertext and tag required"}), 400

    results  = []
    codes    = set()
    t0       = time.time()

    for guess in range(256):
        nonce  = format(guess, "024x")          # crafted nonce, guess embedded
        tampered_ct = format(guess, "0" + str(len(ct)) + "x")[:len(ct)]
        try:
            r = requests.post(f"{GCM_URL}/decrypt", json={
                "nonce":      nonce,
                "ciphertext": tampered_ct,
                "tag":        tag
            }, timeout=5)
            codes.add(r.status_code)
            results.append(r.status_code)
        except Exception:
            results.append(0)

    elapsed   = round(time.time() - t0, 2)
    unique    = len(codes)

    return jsonify({
        "total_requests": 256,
        "unique_codes":   unique,
        "codes_seen":     list(codes),
        "elapsed":        elapsed,
        "oracle_signal":  unique > 1,   # True = vulnerable, False = safe
        "verdict":        "SAFE — all responses identical, no oracle signal"
                          if unique == 1 else "VULNERABLE — different responses detected"
    })


# ── Main route ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("defense.html")


if __name__ == "__main__":
    print("[*] Defense visualizer running at http://127.0.0.1:5003")
    print("[*] Make sure phase3/server.py is running on port 5001")
    app.run(host="127.0.0.1", port=5003, debug=False, threaded=True)