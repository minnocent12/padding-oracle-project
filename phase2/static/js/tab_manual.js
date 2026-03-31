// ══════════════════════════════════════════════════════════════
// tab_manual.js — Attacker Tool tab logic (Tab 3)
// Loaded by visualizer.html for the 🕵️ Attacker Tool tab.
// ══════════════════════════════════════════════════════════════

// All requests go to port 5002 (same origin as this page).
// Flask proxies them to the CBC server on port 5000 to avoid CORS errors.
const ENCRYPT_URL = "/proxy/encrypt";
const DECRYPT_URL = "/proxy/decrypt";

// ── Section 1: Manual Oracle Probe ───────────────────────────

async function manualDecrypt() {
  const iv  = document.getElementById("man-iv").value.trim();
  const ct  = document.getElementById("man-ct").value.trim();
  const box = document.getElementById("man-resp");

  if (!iv || !ct) {
    box.className   = "resp-box resp-info";
    box.textContent = "⚠ Please enter both IV and Ciphertext in hex format.";
    return;
  }

  box.className   = "resp-box resp-neutral";
  box.textContent = "⏳ Sending to oracle...";

  try {
    const r    = await fetch(DECRYPT_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ iv, ciphertext: ct })
    });
    const code = r.status;
    let body = "";
    try { body = JSON.stringify(await r.json(), null, 2); }
    catch { body = "(no response body)"; }

    if (code === 200) {
      box.className   = "resp-box resp-200";
      box.textContent =
        `✔ HTTP 200 — VALID PADDING\n\n` +
        `The server accepted this ciphertext.\n` +
        `In the automated attack, this means the current guess is CORRECT.\n` +
        `The intermediate byte can now be calculated via XOR.\n\n` +
        `Response body:\n${body}`;
    } else {
      box.className   = "resp-box resp-403";
      box.textContent =
        `✘ HTTP ${code} — INVALID PADDING\n\n` +
        `The server rejected this ciphertext.\n` +
        `In the automated attack, this means the current guess is WRONG.\n` +
        `The attacker moves to the next guess value (0x00 → 0xFF).\n\n` +
        `Response body:\n${body}`;
    }
  } catch (e) {
    box.className   = "resp-box resp-403";
    box.textContent = `❌ Connection error: ${e.message}\n\nIs the CBC server running on port 5000?`;
  }
}

function scrollToEncrypt() {
  document.getElementById("man-enc-panel").scrollIntoView({ behavior: "smooth" });
}

function clearManual() {
  document.getElementById("man-iv").value = "";
  document.getElementById("man-ct").value = "";
  const box       = document.getElementById("man-resp");
  box.className   = "resp-box resp-neutral";
  box.textContent = "Awaiting request — paste IV + Ciphertext above and click Send to Oracle.";
}

// ── Section 2: Encrypt First Helper ──────────────────────────

async function encryptForManual() {
  const pt = document.getElementById("man-pt").value.trim();
  if (!pt) { alert("Enter a plaintext."); return; }

  try {
    const r = await fetch(ENCRYPT_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ plaintext: pt })
    });
    if (!r.ok) { alert("Encryption failed — is the CBC server running?"); return; }

    const d = await r.json();

    document.getElementById("man-enc-iv").textContent    = d.iv;
    document.getElementById("man-enc-ct").textContent    = d.ciphertext;
    document.getElementById("man-enc-result").style.display = "block";

    const msg = document.getElementById("man-enc-msg");
    msg.style.display = "block";
    msg.textContent   =
      `✔ Encrypted "${pt}" → ${Math.ceil(pt.length / 16)} block(s). ` +
      `IV and Ciphertext auto-filled into the oracle fields above.`;

    // Auto-fill the oracle probe fields
    document.getElementById("man-iv").value = d.iv;
    document.getElementById("man-ct").value = d.ciphertext;

  } catch (e) {
    alert("Cannot reach CBC server: " + e.message);
  }
}

function copyToManual(which) {
  if (which === "iv") {
    document.getElementById("man-iv").value =
      document.getElementById("man-enc-iv").textContent;
  } else {
    document.getElementById("man-ct").value =
      document.getElementById("man-enc-ct").textContent;
  }
}

// ── Section 3: Crafted Block Probe ───────────────────────────

async function craftedProbe() {
  const ct    = document.getElementById("craft-ct").value.trim();
  const pos   = parseInt(document.getElementById("craft-pos").value)   || 0;
  const guess = parseInt(document.getElementById("craft-guess").value) || 0;
  if (!ct) { alert("Enter a ciphertext block."); return; }

  // Build crafted IV: all zeros except at pos = guess
  const crafted  = new Array(32).fill("0");
  const hex      = guess.toString(16).padStart(2, "0");
  crafted[pos * 2]     = hex[0];
  crafted[pos * 2 + 1] = hex[1];
  const craftedHex = crafted.join("");

  document.getElementById("craft-sent").className   = "resp-box resp-neutral";
  document.getElementById("craft-sent").textContent =
    `POST /decrypt\n{\n  "iv": "${craftedHex}",\n  "ciphertext": "${ct}"\n}` +
    `\n\nCrafted IV byte at position [${pos}] = 0x${hex}`;

  const box       = document.getElementById("craft-resp");
  box.className   = "resp-box resp-neutral";
  box.textContent = "⏳ Sending...";

  try {
          const r = await fetch(DECRYPT_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ iv: craftedHex, ciphertext: ct })
    });

    if (r.status === 200) {
      box.className   = "resp-box resp-200";
      box.textContent =
        `✔ HTTP 200 — VALID PADDING!\n\n` +
        `Guess 0x${hex} at byte position [${pos}] produced valid padding.\n\n` +
        `This is the oracle signal. The intermediate byte at position [${pos}] is:\n` +
        `  intermediate[${pos}] = 0x${hex} ⊕ pad_value\n\n` +
        `XOR with the real IV / prev-block byte at [${pos}] gives the plaintext byte.\n` +
        `This is exactly what the automated attack does — for all 16 bytes.`;
    } else {
      box.className   = "resp-box resp-403";
      box.textContent =
        `✘ HTTP ${r.status} — Invalid padding.\n\n` +
        `Guess 0x${hex} at position [${pos}] did not produce valid padding.\n` +
        `Try a different guess value or use the Brute-force button.`;
    }
  } catch (e) {
    box.className   = "resp-box resp-403";
    box.textContent = `❌ ${e.message}`;
  }
}

// ── Brute-force one byte ──────────────────────────────────────

let bruteRunning = false;

async function bruteOneByte() {
  if (bruteRunning) { bruteRunning = false; return; }

  const ct  = document.getElementById("craft-ct").value.trim();
  const pos = parseInt(document.getElementById("craft-pos").value) || 0;
  if (!ct) { alert("Enter a ciphertext block first."); return; }

  bruteRunning = true;
  const btn = document.querySelector("[onclick='bruteOneByte()']");
  btn.textContent = "⏹ Stop Brute-force";

  const prog = document.getElementById("brute-progress");
  const bar  = document.getElementById("brute-bar");
  const stat = document.getElementById("brute-status");
  prog.style.display = "block";

  const box = document.getElementById("craft-resp");

  for (let g = 0; g <= 255; g++) {
    if (!bruteRunning) break;

    const crafted = new Array(32).fill("0");
    const hex     = g.toString(16).padStart(2, "0");
    crafted[pos * 2]     = hex[0];
    crafted[pos * 2 + 1] = hex[1];
    const craftedHex = crafted.join("");

    bar.style.width  = `${Math.round(g / 255 * 100)}%`;
    stat.textContent = `Trying 0x${hex} (${g}/255)...`;

    try {
      const r = await fetch(DECRYPT_URL, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ iv: craftedHex, ciphertext: ct })
      });

      if (r.status === 200) {
        bar.style.width   = "100%";
        box.className     = "resp-box resp-200";
        box.textContent   =
          `✔ FOUND! Guess 0x${hex} (decimal ${g}) at byte [${pos}] produced valid padding!\n\n` +
          `This took ${g + 1} oracle queries.\n` +
          `intermediate[${pos}] = 0x${hex} ⊕ pad_value\n` +
          `plaintext[${pos}]    = intermediate[${pos}] ⊕ prev_block[${pos}]\n\n` +
          `This is exactly what the automated attack does — for all 16 bytes × all blocks.`;
        stat.textContent  = `✔ Found at 0x${hex} after ${g + 1} queries`;
        bruteRunning      = false;
        break;
      }
    } catch (e) {
      box.className   = "resp-box resp-403";
      box.textContent = `Error: ${e.message}`;
      break;
    }
  }

  btn.textContent = "🔁 Brute-force This Byte (0–255)";
  if (bruteRunning) {
    stat.textContent = "No valid padding found across all 256 guesses.";
    bruteRunning     = false;
  }
}