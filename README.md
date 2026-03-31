# Breaking and Fixing Block Cipher Encryption
### A Practical Study of Padding Oracle Attacks and AEAD Migration

**Author:** Mirenge Innocent
**Course:** Applied Cryptography — Spring 2026

---

## Overview

This project is a full-stack cryptographic vulnerability study demonstrating how AES-CBC encryption is vulnerable to padding oracle attacks, implementing a live byte-wise attack with browser visualization, then proving that migrating to AES-256-GCM completely eliminates the attack surface. The project spans four interconnected phases, each running as an independent server with its own browser UI.

| Phase | Description | Port |
|---|---|---|
| Phase 1 | Vulnerable AES-CBC server with live internals visualization | 5000 |
| Phase 2 | Padding oracle attack engine + attacker tool + GCM probe | 5002 |
| Phase 3 | Secure AES-GCM server with encryption/decryption pipeline | 5001 |
| Phase 4 | Live analytics dashboard + PDF report export | 5004 |

---

## Project Structure

```
padding_oracle_project/
├── phase1/
│   ├── server.py                    # Vulnerable AES-CBC Flask server
│   ├── crypto_utils.py              # AES-CBC + PKCS#7 implementation
│   ├── .env.example                 # Example environment file
│   └── templates/
│       └── index.html               # Interactive encryption/decryption UI
│
├── phase2/
│   ├── attack_visualizer.py         # Attack server + proxy routes (port 5002)
│   ├── attack.py                    # Terminal-based attack script
│   ├── dashboard.py                 # Matplotlib stats dashboard (offline)
│   ├── templates/
│   │   ├── visualizer.html          # Base layout + CSS
│   │   └── tabs/
│   │       ├── tab_attack.html      # Live Attack tab
│   │       ├── tab_howit.html       # How It Works tab
│   │       ├── tab_manual.html      # Attacker Tool tab
│   │       └── gcm/
│   │           ├── tab_gcm_attack.html   # GCM Oracle Probe tab
│   │           ├── tab_gcm_result.html   # GCM Results tab
│   │           └── tab_gcm_why.html      # Why It Fails tab
│   └── static/js/
│       ├── tab_attack.js            # Live attack logic
│       ├── tab_manual.js            # Attacker tool logic
│       └── tab_gcm_attack.js        # GCM probe logic
│
├── phase3/
│   ├── server.py                    # Secure AES-GCM server + UI (port 5001)
│   ├── templates/
│   │   ├── gcm.html                 # Base layout + CSS
│   │   └── tabs/
│   │       ├── tab_encrypt.html     # Encryption pipeline tab
│   │       ├── tab_decrypt.html     # Decryption pipeline tab
│   │       └── tab_howit.html       # How It Works tab
│   └── static/js/
│       ├── tab_encrypt.js           # Encryption pipeline logic
│       └── tab_decrypt.js           # Decryption pipeline logic
│
├── phase4/
│   ├── server.py                    # Dashboard + PDF export server (port 5004)
│   ├── attack_stats.json            # Written by Phase 2, read by Phase 4
│   └── templates/
│       └── dashboard.html           # 5-tab analytics dashboard
│
├── requirements.txt
├── .env.example
└── README.md
```

---

## Setup

### 1. Clone or create the project folder

```bash
git clone https://github.com/minnocent12/padding-oracle-project.git
cd padding-oracle-project
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install all dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the environment file

```bash
cp .env.example .env
```

The `.env` file sets the AES-CBC secret key for Phase 1. The default value works out of the box. Do not use the default key in any real system.

---

## Running Each Phase

All four phases can run simultaneously. Open a separate terminal for each.

### Phase 1 — Vulnerable AES-CBC Server

```bash
cd phase1
python server.py
```

**URL:** http://127.0.0.1:5000

The server runs AES-128-CBC with PKCS#7 padding and **intentionally leaks padding validity** through HTTP response codes:
- `HTTP 200` — padding is valid
- `HTTP 403` — padding is invalid ← this is the oracle signal

The browser UI has three tabs: **Encryption** (step-by-step byte visualization), **Decryption + Oracle** (live oracle signal with padding analysis), and **How It Works** (PKCS#7 reference).

---

### Phase 2 — Padding Oracle Attack

> Phase 1 must be running before starting Phase 2.

**Option A — Terminal attack:**

```bash
cd phase2
python attack.py                        # interactive prompt
python attack.py "Hello World"          # attack a specific message
python attack.py "My secret message"    # any length works
```

**Option B — Browser visualization:**

```bash
cd phase2
python attack_visualizer.py
```

**URL:** http://127.0.0.1:5002

The browser UI has two top-level sections:

**⚔ Attack AES-CBC Server** — three tabs:
- **Live Attack:** type any plaintext, watch byte recovery in real time via SSE streaming
- **How It Works:** step-by-step explanation of the attack algorithm and XOR math
- **Attacker Tool:** manually probe the oracle, craft IV bytes, brute-force a single byte

**🛡 Attack AES-GCM Server** — three tabs (requires Phase 3 running):
- **Oracle Probe:** encrypt a message via GCM, run 256 tampered requests, observe all-403 silence
- **Results:** response breakdown + CBC vs GCM comparison
- **Why It Fails:** explanation of why authenticated encryption prevents the oracle

**Option C — Offline Matplotlib dashboard** (requires `phase4/attack_stats.json` from a prior attack run):

```bash
cd phase2
python dashboard.py
```

---

### Phase 3 — Secure AES-GCM Server

```bash
cd phase3
python server.py
```

**URL:** http://127.0.0.1:5001

The server runs AES-256-GCM with a 96-bit random nonce and 128-bit authentication tag. The auth tag is verified **before** decryption begins. Any tampered ciphertext returns the same generic `HTTP 403` — no padding oracle is possible.

The browser UI has three tabs:
- **Encryption:** 5-step live pipeline (read plaintext → generate nonce → AES-CTR encrypt → compute GHASH tag → package output)
- **Decryption:** 5-step live pipeline showing tag verification before decrypt; the **Tamper Then Decrypt** button demonstrates auth tag catching modification at Step 3
- **How It Works:** GCM internals, CBC vs GCM comparison table, CVE history

---

### Phase 4 — Analytics Dashboard

> Requires Phase 1, Phase 2 (with at least one completed attack), and Phase 3 running.

```bash
cd phase4
python server.py
```

**URL:** http://127.0.0.1:5004

The dashboard has five tabs:
- **Overview:** live server status for all phases, key stats at a glance
- **Attack Stats:** queries-per-byte bar chart, query distribution breakdown, efficiency analysis
- **CBC vs GCM:** side-by-side comparison table + live GCM oracle probe
- **Timeline:** project phase timeline + animated attack replay
- **Report:** full project report preview + **PDF export**

---

### Presentation Generator

Generates a 14-slide professional PowerPoint presentation (widescreen 16:9, dark theme):

```bash
python generate_presentation.py
# Output: padding_oracle_presentation.pptx
```

```bash
pip install python-pptx   # if not already installed
```

---

## Dependencies

```
flask
python-dotenv
pycryptodome
cryptography
requests
rich
matplotlib
numpy
reportlab
python-pptx
```

Install all at once:

```bash
pip install -r requirements.txt
```

---

## Key Concepts

### Why AES-CBC Is Vulnerable

AES-CBC requires PKCS#7 padding on every message. On decryption, the server checks whether the padding is valid. If the server returns a different response for valid versus invalid padding — even just different HTTP status codes — an attacker can:

1. Submit crafted ciphertexts with one modified byte
2. Observe whether the response is `200` (valid padding) or `403` (invalid)
3. Use XOR arithmetic to recover the intermediate AES output
4. Compute the plaintext byte from the intermediate and the real ciphertext

Repeating this for all 16 bytes per block and all blocks recovers the full plaintext. The secret key is **never needed**.

```
Expected queries:  ~128 per byte  (average)
Worst case:        256 per byte
16-byte message:   ~2,048 total HTTP requests → full plaintext
```

### Why AES-GCM Is Safe

AES-GCM uses authenticated encryption. Before decryption begins, the server recomputes the GHASH authentication tag over the received ciphertext and compares it to the transmitted tag. If they do not match — which is always the case for tampered attacker-crafted ciphertext — the request is rejected with a generic error. No decryption occurs. No padding check occurs. No oracle signal is produced.

```
256 oracle guesses against CBC:  ~1 HTTP 200 → byte recovered
256 oracle guesses against GCM:  256 × HTTP 403 → nothing learned
```

### XOR Math Summary

```
# When oracle returns HTTP 200 for guess at byte position j:

intermediate[j] = guess ⊕ pad_value
plaintext[j]    = intermediate[j] ⊕ prev_ciphertext_block[j]

# Two XOR operations. No key. Full plaintext byte recovered.
```

---

## Real-World CVEs

| CVE | Name | Year | System | Impact |
|---|---|---|---|---|
| CVE-2014-3566 | POODLE | 2014 | SSL 3.0 | Forced deprecation of SSL 3.0 globally |
| CVE-2013-0169 | Lucky Thirteen | 2013 | TLS 1.0/1.1/1.2 | Timing-based oracle; required TLS library patches |
| CVE-2010-3332 | ASP.NET Oracle | 2010 | ASP.NET ViewState | Session cookie decryption; emergency Microsoft patch |

---

## Security Recommendations

| ✔ Do | ✗ Do not |
|---|---|
| Use AES-GCM or ChaCha20-Poly1305 | Use AES-CBC for new systems |
| Verify integrity before decrypting | Decrypt then check padding |
| Return the same error for all failures | Differentiate padding vs auth errors |
| Use constant-time tag comparison | Use early-exit equality checks |
| Use a fresh random nonce every encryption | Reuse a nonce with the same key |

---

## License

This project is intended for educational purposes in a graduate cryptography course. All implementations are original. Do not use the vulnerable Phase 1 server in any production environment.