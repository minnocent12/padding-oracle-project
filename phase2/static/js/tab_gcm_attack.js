// ══════════════════════════════════════════════════════════════
// tab_gcm_attack.js — GCM Oracle Probe logic (Phase 2, GCM section)
// ══════════════════════════════════════════════════════════════

let gcmProbeData = null;   // stored for Results tab

// ── Encrypt via GCM server ────────────────────────────────────

async function gcmAtkEncrypt() {
  const pt = document.getElementById("gcm-atk-pt").value.trim();
  if (!pt) { alert("Enter a plaintext."); return; }

  const btn = document.getElementById("btn-gcm-encrypt");
  btn.disabled = true;

  try {
    const r = await fetch("/proxy/gcm/encrypt", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ plaintext: pt })
    });
    const d = await r.json();
    if (!r.ok) {
      alert("Encryption failed: " + (d.error || "unknown error"));
      btn.disabled = false;
      return;
    }

    document.getElementById("gcm-atk-nonce").textContent = d.nonce;
    document.getElementById("gcm-atk-ct").textContent    = d.ciphertext;
    document.getElementById("gcm-atk-tag").textContent   = d.tag;
    document.getElementById("gcm-atk-enc-result").style.display = "block";
    document.getElementById("btn-gcm-probe").disabled    = false;

  } catch (e) {
    alert("Cannot reach GCM server: " + e.message);
  }
  btn.disabled = false;
}

// ── Run the 256-request oracle probe ─────────────────────────

async function gcmRunProbe() {
  const ct  = document.getElementById("gcm-atk-ct").textContent.trim();
  const tag = document.getElementById("gcm-atk-tag").textContent.trim();
  if (!ct || ct === "—") { alert("Encrypt something first."); return; }

  // Show panels
  document.getElementById("gcm-probe-running").style.display = "block";
  document.getElementById("gcm-probe-panel").style.display   = "block";
  document.getElementById("gcm-verdict").style.display       = "none";
  document.getElementById("gcm-probe-grid").innerHTML        = "";
  document.getElementById("btn-gcm-probe").disabled          = true;

  const bar    = document.getElementById("gcm-probe-bar");
  const status = document.getElementById("gcm-probe-status");
  bar.style.width  = "10%";
  status.textContent = "Sending 256 tampered requests to GCM server...";

  try {
    const r = await fetch("/proxy/gcm/probe", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ ciphertext: ct, tag })
    });
    const d = await r.json();

    bar.style.width = "100%";
    status.textContent = `Complete — ${d.total} requests sent in ${d.elapsed}s`;

    // Build response grid
    const grid = document.getElementById("gcm-probe-grid");
    grid.innerHTML = "";
    d.results.forEach(res => {
      const cell = document.createElement("div");
      cell.className = `probe-cell ${res.code === 200 ? "pc-200" : "pc-403"}`;
      cell.textContent = res.code || "err";
      cell.title = `Request ${res.guess}: HTTP ${res.code}`;
      grid.appendChild(cell);
    });

    // Update stats
    document.getElementById("gcm-p-total").textContent = d.total;
    const uniqEl = document.getElementById("gcm-p-unique");
    uniqEl.textContent = d.unique_codes;
    uniqEl.style.color = d.unique_codes === 1 ? "#3fb950" : "#f85149";
    document.getElementById("gcm-p-elapsed").textContent = d.elapsed + "s";

    // Verdict
    const verdict = document.getElementById("gcm-verdict");
    verdict.style.display = "block";
    verdict.className = d.oracle_signal ? "verdict v-vuln" : "verdict v-safe";
    verdict.innerHTML = d.oracle_signal
      ? `✘ ORACLE SIGNAL DETECTED — server is vulnerable`
      : `✔ NO ORACLE SIGNAL — all ${d.total} responses are HTTP 403 · Attack impossible`;

    // Store for Results tab and populate it
    gcmProbeData = d;
    populateResultsTab(d);

  } catch (e) {
    status.textContent = "Error: " + e.message;
  }

  document.getElementById("btn-gcm-probe").disabled = false;
}

// ── Populate Results tab ──────────────────────────────────────

function populateResultsTab(d) {
  document.getElementById("gcm-result-empty").style.display   = "none";
  document.getElementById("gcm-result-content").style.display = "block";

  document.getElementById("res-total").textContent   = d.total;
  document.getElementById("res-elapsed").textContent = d.elapsed + "s";

  const uniqEl = document.getElementById("res-unique");
  uniqEl.textContent = d.unique_codes;
  uniqEl.style.color = d.unique_codes === 1 ? "#3fb950" : "#f85149";

  // Verdict
  const v = document.getElementById("res-verdict");
  v.className = d.oracle_signal ? "verdict v-vuln" : "verdict v-safe";
  v.innerHTML = d.oracle_signal
    ? `✘ ORACLE SIGNAL DETECTED — server is vulnerable`
    : `✔ NO ORACLE SIGNAL — all ${d.total} responses identical (HTTP 403) · Padding oracle impossible`;

  // GCM signal summary line
  const sig = document.getElementById("res-gcm-signal");
  if (!d.oracle_signal) {
    sig.textContent = `All ${d.total} requests → HTTP 403 → no oracle → attack impossible ✔`;
  } else {
    sig.textContent = `⚠ Some requests returned HTTP 200 — oracle signal present!`;
    sig.style.color = "#f85149";
  }

  // Response code breakdown
  const codeMap = {};
  d.results.forEach(r => {
    codeMap[r.code] = (codeMap[r.code] || 0) + 1;
  });
  const breakdown = document.getElementById("res-codes-breakdown");
  breakdown.innerHTML = Object.entries(codeMap).map(([code, count]) => {
    const pct   = Math.round(count / d.total * 100);
    const color = code === "200" ? "#3fb950" : code === "403" ? "#f85149" : "#8b949e";
    return `
      <div style="margin-bottom:.6rem">
        <div style="display:flex;justify-content:space-between;
                    font-size:.78rem;margin-bottom:3px">
          <span style="color:${color};font-weight:bold">HTTP ${code}</span>
          <span class="dim">${count} / ${d.total} requests (${pct}%)</span>
        </div>
        <div class="prog-wrap">
          <div class="prog-bar" style="width:${pct}%;background:${color}"></div>
        </div>
      </div>`;
  }).join("");

  // Full grid replay
  const grid = document.getElementById("res-probe-grid");
  grid.innerHTML = "";
  d.results.forEach(res => {
    const cell = document.createElement("div");
    cell.className = `probe-cell ${res.code === 200 ? "pc-200" : "pc-403"}`;
    cell.textContent = res.code || "err";
    cell.title = `Request ${res.guess}: HTTP ${res.code}`;
    grid.appendChild(cell);
  });
}

// ── Reset ─────────────────────────────────────────────────────

function gcmReset() {
  gcmProbeData = null;

  document.getElementById("gcm-atk-enc-result").style.display  = "none";
  document.getElementById("gcm-probe-running").style.display   = "none";
  document.getElementById("gcm-probe-panel").style.display     = "none";
  document.getElementById("gcm-probe-grid").innerHTML          = "";
  document.getElementById("gcm-verdict").style.display         = "none";
  document.getElementById("gcm-probe-bar").style.width         = "0";
  document.getElementById("gcm-probe-status").textContent      = "Waiting...";
  document.getElementById("gcm-p-total").textContent           = "0";
  document.getElementById("gcm-p-unique").textContent          = "—";
  document.getElementById("gcm-p-elapsed").textContent         = "—";
  document.getElementById("btn-gcm-probe").disabled            = true;

  // Reset results tab
  document.getElementById("gcm-result-empty").style.display    = "block";
  document.getElementById("gcm-result-content").style.display  = "none";
}