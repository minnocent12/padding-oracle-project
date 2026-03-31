"""
phase4/server.py — Dashboard + Report server.
Runs on port 5004. Pulls live data from all running servers.

Requires:
  phase1/server.py   → port 5000 (CBC)
  phase3/server.py   → port 5001 (GCM)
  phase2/attack_visualizer.py → port 5002 (attack stats)

Run:
    cd phase4
    python server.py
Then open: http://127.0.0.1:5004
"""

import json, os, time, requests
from datetime import datetime
from flask import Flask, render_template, jsonify, Response
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable)

app        = Flask(__name__)
STATS_FILE = "../phase4/attack_stats.json"
CBC_URL    = "http://127.0.0.1:5000"
GCM_URL    = "http://127.0.0.1:5001"


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_stats() -> dict:
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE) as f:
        return json.load(f)


def probe_server(url: str, name: str) -> dict:
    """
    Check if a server is reachable.
    Tries /status first; if 404 falls back to GET / to confirm the port is alive.
    """
    try:
        # Try /status endpoint first
        r = requests.get(f"{url}/status", timeout=3)
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                data = {}
            return {"name": name, "url": url, "online": True,
                    "status": data, "code": 200}

        # /status returned something other than 200 (e.g. 404 on older Phase 1)
        # Fall back: hit GET / to confirm port is alive
        r2 = requests.get(f"{url}/", timeout=3)
        return {"name": name, "url": url, "online": True,
                "status": {"note": "/status not available, port is alive"},
                "code": r2.status_code}

    except requests.exceptions.ConnectionError:
        return {"name": name, "url": url, "online": False,
                "error": "Connection refused", "code": 0}
    except requests.exceptions.Timeout:
        return {"name": name, "url": url, "online": False,
                "error": "Timeout", "code": 0}
    except Exception as e:
        return {"name": name, "url": url, "online": False,
                "error": str(e), "code": 0}


def run_gcm_probe_sample(n: int = 16) -> dict:
    """Send n tampered decrypt requests to GCM to demonstrate oracle silence."""
    results, codes = [], set()
    for i in range(n):
        nonce = format(i, "024x")
        ct    = format(i * 7 + 13, "032x")
        tag   = "0" * 32
        try:
            r = requests.post(f"{GCM_URL}/decrypt",
                              json={"nonce": nonce, "ciphertext": ct, "tag": tag},
                              timeout=3)
            codes.add(r.status_code)
            results.append(r.status_code)
        except Exception:
            results.append(0)
    return {"results": results, "unique": list(codes), "silent": len(codes) == 1}


# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    cbc = probe_server(CBC_URL, "AES-CBC (Phase 1)")
    gcm = probe_server(GCM_URL, "AES-GCM (Phase 3)")
    return jsonify({"cbc": cbc, "gcm": gcm,
                    "timestamp": datetime.now().isoformat()})


@app.route("/api/stats")
def api_stats():
    stats = load_stats()
    if not stats:
        return jsonify({"error": "No attack stats found. Run Phase 2 first."}), 404

    per_byte = stats.get("per_byte", [])
    total_q  = stats.get("total_queries", 0)
    n        = len(per_byte)

    return jsonify({
        **stats,
        "n_bytes":    n,
        "avg":        round(total_q / max(n, 1), 1),
        "max_q":      max(per_byte) if per_byte else 0,
        "min_q":      min(per_byte) if per_byte else 0,
        "worst_case": n * 256,
        "efficiency": round((1 - total_q / max(n * 256, 1)) * 100, 1),
    })


@app.route("/api/gcm_probe")
def api_gcm_probe():
    try:
        result = run_gcm_probe_sample(16)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cbc_encrypt_sample")
def api_cbc_encrypt_sample():
    try:
        r = requests.post(f"{CBC_URL}/encrypt",
                          json={"plaintext": "Phase4 Demo"},
                          timeout=3)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 503


# ── PDF export ────────────────────────────────────────────────────────────────

@app.route("/export/pdf")
def export_pdf():
    stats     = load_stats()
    per_byte  = stats.get("per_byte", [])
    total_q   = stats.get("total_queries", 0)
    n         = len(per_byte)
    avg       = round(total_q / max(n, 1), 1)
    target    = stats.get("target", "N/A")
    recovered = stats.get("recovered", "N/A")
    timestamp = datetime.now().strftime("%B %d, %Y at %H:%M")

    cbc_status = probe_server(CBC_URL, "CBC")
    gcm_status = probe_server(GCM_URL, "GCM")

    from io import BytesIO
    buf  = BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=letter,
                              leftMargin=0.9*inch, rightMargin=0.9*inch,
                              topMargin=0.9*inch, bottomMargin=0.9*inch)

    styles = getSampleStyleSheet()
    RED    = colors.HexColor("#c0392b")
    GREEN  = colors.HexColor("#27ae60")
    BLUE   = colors.HexColor("#2980b9")
    DARK   = colors.HexColor("#1a1a2e")
    GRAY   = colors.HexColor("#7f8c8d")

    def H1(text):
        return Paragraph(text, ParagraphStyle("h1", parent=styles["Heading1"],
            textColor=DARK, fontSize=18, spaceAfter=6))
    def H2(text, color=BLUE):
        return Paragraph(text, ParagraphStyle("h2", parent=styles["Heading2"],
            textColor=color, fontSize=13, spaceAfter=4))
    def H3(text):
        return Paragraph(text, ParagraphStyle("h3", parent=styles["Heading3"],
            textColor=DARK, fontSize=11, spaceAfter=3))
    def P(text):
        return Paragraph(text, ParagraphStyle("body", parent=styles["Normal"],
            fontSize=10, leading=15, spaceAfter=6))
    def HR():
        return HRFlowable(width="100%", thickness=1,
                          color=colors.HexColor("#bdc3c7"), spaceAfter=8)
    def SP(h=8):
        return Spacer(1, h)

    story = []

    story += [
        SP(20),
        Paragraph("Padding Oracle Attack", ParagraphStyle("cover_title",
            parent=styles["Title"], fontSize=28, textColor=RED,
            alignment=1, spaceAfter=4)),
        Paragraph("Full Project Report", ParagraphStyle("cover_sub",
            parent=styles["Normal"], fontSize=16, textColor=DARK,
            alignment=1, spaceAfter=4)),
        Paragraph(f"Generated: {timestamp}", ParagraphStyle("cover_date",
            parent=styles["Normal"], fontSize=10, textColor=GRAY,
            alignment=1, spaceAfter=20)),
        HR(), SP(8),
    ]

    story += [
        H1("Executive Summary"),
        P("This project demonstrates the Padding Oracle Attack against AES-CBC "
          "encryption and its defense using AES-GCM. The attack exploits a "
          "vulnerability in CBC mode combined with leaky error handling to recover "
          "plaintext without ever knowing the secret key. Phase 3 shows that "
          "switching to AES-GCM authenticated encryption completely eliminates "
          "the vulnerability."),
        SP(4),
    ]

    story += [
        HR(), H2("Phase 1 — Vulnerable AES-CBC Server", RED),
        H3("What Was Built"),
        P("A Flask server running on port 5000 implementing AES-128-CBC encryption "
          "and decryption. The server intentionally leaks padding validity through "
          "its HTTP response codes: HTTP 200 for valid padding and HTTP 403 for "
          "invalid padding."),
        H3("The Vulnerability"),
        P("AES-CBC requires PKCS#7 padding and checks it on every decryption. "
          "By returning different responses for valid vs invalid padding, the server "
          "creates an oracle — an information source the attacker can query to "
          "learn about the plaintext byte by byte."),
        H3("Server Status"),
        P(f"CBC Server (port 5000): {'Online' if cbc_status['online'] else 'Offline'}"),
        SP(4),
    ]

    story += [
        HR(), H2("Phase 2 — Padding Oracle Attack", RED),
        H3("Attack Overview"),
        P("The attack targets the CBC server's decryption endpoint by sending "
          "crafted ciphertext blocks and observing HTTP 200 vs 403 responses. "
          "It works byte by byte, right to left, using XOR arithmetic to recover "
          "the intermediate state and then the plaintext."),
    ]

    if stats:
        story += [
            H3("Attack Results"),
            Table([
                ["Metric", "Value"],
                ["Target plaintext",      target],
                ["Recovered text",        recovered],
                ["Match",                 "YES" if target == recovered else "NO"],
                ["Total oracle queries",  str(total_q)],
                ["Bytes recovered",       str(n)],
                ["Average queries/byte",  str(avg)],
                ["Max queries/byte",      str(max(per_byte)) if per_byte else "N/A"],
                ["Min queries/byte",      str(min(per_byte)) if per_byte else "N/A"],
                ["Worst case possible",   str(n * 256)],
                ["Efficiency vs worst",   f"{round((1 - total_q/max(n*256,1))*100,1)}%"],
            ], colWidths=[3*inch, 3.5*inch],
            style=TableStyle([
                ("BACKGROUND", (0,0), (-1,0), BLUE),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS", (0,1), (-1,-1),
                 [colors.HexColor("#f8f9fa"), colors.white]),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#dee2e6")),
                ("LEFTPADDING",(0,0), (-1,-1), 8),
                ("RIGHTPADDING",(0,0),(-1,-1), 8),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ])),
            SP(8),
        ]

        if per_byte:
            story.append(H3("Queries per Byte"))
            rows = [["Byte", "Queries"] * 4]
            row  = []
            for i, q in enumerate(per_byte):
                row += [str(i), str(q)]
                if len(row) == 8:
                    rows.append(row); row = []
            if row:
                rows.append(row + [""] * (8 - len(row)))
            story += [
                Table(rows, colWidths=[0.45*inch]*8,
                      style=TableStyle([
                          ("FONTSIZE",  (0,0), (-1,-1), 8),
                          ("GRID",      (0,0), (-1,-1), 0.3, colors.HexColor("#dee2e6")),
                          ("BACKGROUND",(0,0), (-1,0), colors.HexColor("#e9ecef")),
                          ("ALIGN",     (0,0), (-1,-1), "CENTER"),
                          ("TOPPADDING",(0,0),(-1,-1), 3),
                          ("BOTTOMPADDING",(0,0),(-1,-1), 3),
                      ])),
                SP(8),
            ]
    else:
        story += [P("No attack stats found. Run Phase 2 first."), SP(4)]

    story += [
        HR(), H2("Phase 3 — AES-GCM Defense", GREEN),
        H3("What Was Built"),
        P("A Flask server running on port 5001 implementing AES-256-GCM "
          "authenticated encryption. GCM produces three values per encryption: "
          "a 96-bit random nonce, the ciphertext, and a 128-bit authentication tag."),
        H3("Why the Attack Fails"),
        P("GCM verifies the authentication tag before decryption begins. Any "
          "tampered ciphertext produces a tag mismatch and is rejected with a "
          "generic HTTP 403 — always the same response regardless of the input. "
          "There is no padding to exploit and no oracle signal to read."),
        H3("Server Status"),
        P(f"GCM Server (port 5001): {'Online' if gcm_status['online'] else 'Offline'}"),
        SP(4),
    ]

    story += [
        HR(), H2("Phase 4 — CBC vs GCM Comparison", BLUE),
        Table([
            ["Property",              "AES-CBC (Vulnerable)", "AES-GCM (Secure)"],
            ["Mode",                  "Cipher Block Chaining", "Galois/Counter Mode"],
            ["Padding",               "PKCS#7 — required",    "None — stream cipher"],
            ["Authentication",        "None",                  "128-bit GHASH tag"],
            ["Tamper detection",      "No",                    "Yes — before decrypt"],
            ["Error responses",       "Different (oracle)",    "Always identical"],
            ["Padding oracle attack", "Succeeds (~2048 req)",  "Impossible"],
            ["Key size used",         "128-bit",               "256-bit"],
        ], colWidths=[2.2*inch, 2.2*inch, 2.2*inch],
        style=TableStyle([
            ("BACKGROUND", (0,0),  (-1,0),  DARK),
            ("TEXTCOLOR",  (0,0),  (-1,0),  colors.white),
            ("FONTNAME",   (0,0),  (-1,0),  "Helvetica-Bold"),
            ("BACKGROUND", (1,1),  (1,-1),  colors.HexColor("#fff5f5")),
            ("BACKGROUND", (2,1),  (2,-1),  colors.HexColor("#f0fff4")),
            ("TEXTCOLOR",  (1,1),  (1,-1),  RED),
            ("TEXTCOLOR",  (2,1),  (2,-1),  GREEN),
            ("FONTSIZE",   (0,0),  (-1,-1), 9),
            ("GRID",       (0,0),  (-1,-1), 0.5, colors.HexColor("#dee2e6")),
            ("LEFTPADDING",(0,0),  (-1,-1), 8),
            ("TOPPADDING", (0,0),  (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ])),
        SP(8),
    ]

    story += [
        HR(), H2("Conclusions & Recommendations", BLUE),
        H3("Key Findings"),
        P("1. AES-CBC is cryptographically broken in practice when combined with "
          "a decryption oracle. The padding oracle attack recovers full plaintext "
          "in approximately 128 x N requests where N is the number of bytes."),
        P("2. The vulnerability is not in AES itself but in CBC mode combined with "
          "leaky error handling. AES remains unbroken."),
        P("3. AES-GCM completely eliminates the vulnerability through authenticated "
          "encryption. The auth tag verification prevents the oracle from forming."),
        H3("Recommendations"),
        P("Always use AES-GCM or another AEAD cipher instead of AES-CBC for new systems."),
        P("Authenticate before decrypt — verify integrity before processing any encrypted data."),
        P("Return generic errors — never differentiate error responses in ways that "
          "reveal information about internal state."),
        P("Use constant-time comparisons to prevent timing oracles even without "
          "message differences."),
        H3("Real-World Impact"),
        P("This attack technique was used in POODLE (CVE-2014-3566) against SSL 3.0, "
          "Lucky Thirteen (CVE-2013-0169) against TLS CBC, and the ASP.NET padding "
          "oracle (CVE-2010-3332). All forced major protocol and framework changes."),
        SP(16),
        Paragraph(f"Report generated by Phase 4 Dashboard · {timestamp}",
                  ParagraphStyle("footer", parent=styles["Normal"],
                      fontSize=8, textColor=GRAY, alignment=1)),
    ]

    doc.build(story)
    buf.seek(0)

    fname = f"padding_oracle_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(buf.read(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ── Main UI ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


if __name__ == "__main__":
    print("[*] Phase 4 dashboard running at http://127.0.0.1:5004")
    print("[*] Requires phase1, phase2, phase3 servers running")
    app.run(host="127.0.0.1", port=5004, debug=False, threaded=True)