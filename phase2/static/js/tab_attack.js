// ══════════════════════════════════════════════════════════════
// tab_attack.js — Live Attack tab logic (Tab 1)
// Loaded by visualizer.html for the ⚔ Live Attack tab.
// ══════════════════════════════════════════════════════════════

let evtSource   = null;
let startTime   = null;
let timerHandle = null;
let perByte     = [];
let queryCount  = 0;
let byteCount   = 0;
let totalBytes  = 0;
let numBlocks   = 0;
let feedCount   = 0;

// ── Input hint: update block/byte count as user types ─────────
document.getElementById("pt-input").addEventListener("input", function () {
  const len    = this.value.length || 0;
  const blocks = Math.ceil(len / 16) || 1;
  const bytes  = blocks * 16;
  document.getElementById("pt-len").textContent    = len;
  document.getElementById("pt-blocks").textContent = blocks;
  document.getElementById("pt-bytes").textContent  = bytes;
});

// ── Build byte grid for N blocks ──────────────────────────────
function initGrid(n) {
  const c = document.getElementById("byte-grid-container");
  c.innerHTML = "";
  for (let b = 0; b < n; b++) {
    let cells = "";
    for (let i = 0; i < 16; i++) {
      const g = b * 16 + i;
      cells += `
        <div class="byte-cell bc-idle" id="bc-${g}">
          <span class="b-idx">[${i}]</span>
          <span class="b-char" id="bc-char-${g}">?</span>
          <span class="b-hex"  id="bc-hex-${g}">--</span>
        </div>`;
    }
    c.innerHTML += `
      <div class="block-section">
        <div class="block-label">
          <span class="block-badge" id="blk-badge-${b}">Block ${b}</span>
          <span class="dim" style="font-size:.72rem">bytes ${b * 16}–${b * 16 + 15}</span>
        </div>
        <div class="byte-grid">${cells}</div>
      </div>`;
  }
}

// ── Start attack ──────────────────────────────────────────────
async function startAttack() {
  const pt = document.getElementById("pt-input").value.trim();
  if (!pt) { alert("Enter a plaintext first."); return; }
  resetUI(false);

  const r = await fetch("/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plaintext: pt })
  });
  const d = await r.json();
  if (!r.ok) { setStatus("❌ " + (d.error || "Error"), "red"); return; }

  totalBytes = d.total_bytes;
  numBlocks  = d.num_blocks;
  initGrid(numBlocks);

  document.getElementById("ct-iv").textContent      = d.iv;
  document.getElementById("ct-hex").textContent     = d.ct;
  document.getElementById("ct-panel").style.display = "block";
  document.getElementById("s-bytes").textContent    = `0/${totalBytes}`;
  document.getElementById("btn-start").disabled     = true;
  document.getElementById("btn-stop").disabled      = false;

  startTime   = Date.now();
  timerHandle = setInterval(() => {
    document.getElementById("s-elapsed").textContent =
      ((Date.now() - startTime) / 1000).toFixed(1) + "s";
  }, 100);

  evtSource           = new EventSource("/stream");
  evtSource.onmessage = e => handleEvent(JSON.parse(e.data));
  evtSource.onerror   = () => setStatus("SSE connection error", "red");
}

// ── Stop attack ───────────────────────────────────────────────
async function stopAttack() {
  await fetch("/stop", { method: "POST" });
  document.getElementById("btn-stop").disabled = true;
}

// ── Handle SSE events ─────────────────────────────────────────
function handleEvent(ev) {
  switch (ev.type) {

    case "start":
      setStatus(`⚔ Attacking "${ev.target}" — ${ev.blocks} block(s)...`, "yellow");
      break;

    case "block_start": {
      if (ev.block > 0) {
        const prev = document.getElementById(`blk-badge-${ev.block - 1}`);
        if (prev) { prev.className = "block-badge done"; prev.textContent = `Block ${ev.block - 1} ✔`; }
      }
      const cur = document.getElementById(`blk-badge-${ev.block}`);
      if (cur) { cur.className = "block-badge active"; cur.textContent = `Block ${ev.block} ← attacking`; }
      document.getElementById("s-block").textContent = `${ev.block + 1}/${ev.total_blocks}`;
      break;
    }

    case "byte_start":
      setByteActive(ev.global_idx);
      document.getElementById("byte-detail").innerHTML =
        `Block <span class="blue">${ev.block}</span> · ` +
        `Byte <span class="yellow">[${ev.byte_idx}]</span> · ` +
        `Global <span class="dim">${ev.global_idx}</span><br/>` +
        `Target padding: <span class="purple">0x${ev.pad_val.toString(16).padStart(2, "0")}</span> · Trying 0x00 → 0xff...`;
      break;

    case "query":
      queryCount = ev.total_q;
      document.getElementById("s-queries").textContent = ev.total_q;
      addFeedLine(ev);
      break;

    case "verify":
      addFeedLine({ ...ev, isVerify: true });
      break;

    case "byte_found":
      markByteDone(ev);
      showMath(ev);
      updateChart(ev);
      byteCount++;
      document.getElementById("s-bytes").textContent    = `${byteCount}/${totalBytes}`;
      document.getElementById("recovered-str").textContent = ev.recovered_so_far || "—";
      document.getElementById("progress").style.width   = `${Math.round(byteCount / totalBytes * 100)}%`;
      break;

    case "done": {
      clearInterval(timerHandle);
      if (evtSource) evtSource.close();
      const lb = document.getElementById(`blk-badge-${numBlocks - 1}`);
      if (lb) { lb.className = "block-badge done"; lb.textContent = `Block ${numBlocks - 1} ✔`; }
      document.getElementById("btn-start").disabled = false;
      document.getElementById("btn-stop").disabled  = true;
      showResult(ev);
      setStatus("✔ Attack complete", "green");
      break;
    }

    case "stopped":
      clearInterval(timerHandle);
      if (evtSource) evtSource.close();
      document.getElementById("btn-start").disabled = false;
      document.getElementById("btn-stop").disabled  = true;
      setStatus("⏹ Attack stopped", "dim");
      break;
  }
}

// ── Oracle feed ───────────────────────────────────────────────
function addFeedLine(ev) {
  const feed = document.getElementById("oracle-feed");
  feedCount++;
  // Throttle non-notable lines once feed gets long
  if (feedCount > 80 && feedCount % 6 !== 0 && !ev.valid && !ev.isVerify) return;

  const cls = ev.isVerify   ? "feed-line"
            : ev.valid      ? "feed-line feed-found"
            : ev.code === 200 ? "feed-line feed-200"
                              : "feed-line feed-403";
  const tag = ev.isVerify
    ? `<span class="feed-tag tag-verify">VERIFY</span>`
    : ev.valid
      ? `<span class="feed-tag tag-found">HTTP 200 ✔</span>`
      : `<span class="feed-tag ${ev.code === 200 ? "tag-200" : "tag-403"}">HTTP ${ev.code}</span>`;

  feed.insertAdjacentHTML("beforeend", `
    <div class="${cls}">
      ${tag}
      <span class="dim">blk${ev.block ?? 0}·b[${ev.byte_idx}]</span>
      guess=<span class="${ev.valid ? "green" : "dim"}">
        0x${(ev.guess || 0).toString(16).padStart(2, "0")}</span>
      ${ev.valid ? `<span class="green">← FOUND</span>` : ""}
      <span class="dim" style="margin-left:auto">#${ev.total_q}</span>
    </div>`);
  feed.scrollTop = feed.scrollHeight;
}

// ── Byte grid helpers ─────────────────────────────────────────
function setByteActive(g) {
  const el = document.getElementById(`bc-${g}`);
  if (el) el.className = "byte-cell bc-active";
}

function markByteDone(ev) {
  const el = document.getElementById(`bc-${ev.global_idx}`);
  if (el) el.className = `byte-cell ${ev.plain_val === (16 - ev.byte_idx) ? "bc-pad" : "bc-done"}`;
  const ch = document.getElementById(`bc-char-${ev.global_idx}`);
  const hx = document.getElementById(`bc-hex-${ev.global_idx}`);
  if (ch) ch.textContent = ev.plain_char;
  if (hx) hx.textContent = ev.plain_hex;
}

// ── XOR Math box ──────────────────────────────────────────────
function showMath(ev) {
  document.getElementById("math-box").innerHTML = `
    <div style="color:#8b949e;font-size:.72rem;margin-bottom:.4rem">
      Block ${ev.block} · Byte [${ev.byte_idx}] recovered:
    </div>
    <div class="math-row">
      <span class="dim">Step 1:</span>
      <span class="math-val mv-guess">0x${ev.guess_hex}</span>
      <span class="math-op">⊕</span>
      <span class="math-val mv-pad">0x${ev.pad_val.toString(16).padStart(2, "0")}</span>
      <span class="math-eq">=</span>
      <span class="math-val mv-inter">0x${ev.inter_hex}</span>
    </div>
    <div style="font-size:.7rem;color:#6b7280;margin:.1rem 0 .35rem .5rem">
      guess ⊕ pad_value = intermediate byte
    </div>
    <div class="math-row">
      <span class="dim">Step 2:</span>
      <span class="math-val mv-inter">0x${ev.inter_hex}</span>
      <span class="math-op">⊕</span>
      <span class="math-val mv-iv">0x${ev.iv_hex}</span>
      <span class="math-eq">=</span>
      <span class="math-val mv-plain">'${ev.plain_char}' (0x${ev.plain_hex})</span>
    </div>
    <div style="font-size:.7rem;color:#6b7280;margin:.1rem 0 0 .5rem">
      intermediate ⊕ prev_block[${ev.byte_idx}] = plaintext byte
    </div>
    <div class="info" style="margin-top:.5rem;font-size:.73rem">
      Used <span class="yellow">${ev.queries_used}</span> queries ·
      Total: <span class="yellow">${ev.total_q}</span>
    </div>`;
}

// ── Bar chart ─────────────────────────────────────────────────
function updateChart(ev) {
  perByte.push({ idx: ev.global_idx, q: ev.queries_used });
  const maxQ = Math.max(...perByte.map(b => b.q), 1);
  const qs   = perByte.map(b => b.q);

  document.getElementById("avg-q").textContent = (qs.reduce((a, b) => a + b, 0) / qs.length).toFixed(1);
  document.getElementById("max-q").textContent = Math.max(...qs);
  document.getElementById("min-q").textContent = Math.min(...qs);

  document.getElementById("bar-chart").innerHTML = perByte.map(b => {
    const pct = Math.round(b.q / maxQ * 100);
    const col = b.q > 200 ? "#f85149" : b.q > 100 ? "#58a6ff" : "#3fb950";
    return `<div class="bar-col">
      <div class="bar-seg" style="height:${pct}%;background:${col}"></div>
      <div class="bar-lbl">${b.idx}</div>
    </div>`;
  }).join("");
}

// ── Result banner ─────────────────────────────────────────────
function showResult(ev) {
  const b = document.getElementById("result-banner");
  b.style.display = "block";
  b.className = ev.match ? "result-banner res-success" : "result-banner res-fail";
  b.innerHTML = ev.match
    ? `✔ Attack Successful! &nbsp; Recovered: "<strong>${ev.recovered}</strong>"
       &nbsp;·&nbsp; ${ev.total_q} queries &nbsp;·&nbsp; ${ev.elapsed}s
       &nbsp;·&nbsp; avg ${ev.avg} q/byte
       &nbsp;·&nbsp; <span style="color:#e3b341">Zero key knowledge used</span>`
    : `Recovered: "${ev.recovered}" (partial match)`;
}

// ── Status text ───────────────────────────────────────────────
function setStatus(msg, cls) {
  const el = document.getElementById("status-text");
  el.className = cls;
  el.innerHTML = msg.includes("...") ? `<span class="spinner"></span>${msg}` : msg;
}

// ── Full UI reset ─────────────────────────────────────────────
function resetUI(full = true) {
  if (evtSource)   { evtSource.close();        evtSource   = null; }
  if (timerHandle) { clearInterval(timerHandle); timerHandle = null; }

  queryCount = 0; byteCount = 0; perByte = []; feedCount = 0;
  totalBytes = 0; numBlocks = 0;

  document.getElementById("byte-grid-container").innerHTML =
    '<span class="dim" style="font-size:.8rem">Grid appears when attack starts...</span>';
  document.getElementById("oracle-feed").innerHTML   = "";
  document.getElementById("math-box").innerHTML      = '<span class="dim">Waiting for first byte recovery...</span>';
  document.getElementById("byte-detail").innerHTML   = "—";
  document.getElementById("bar-chart").innerHTML     = "";
  document.getElementById("recovered-str").textContent = "—";
  document.getElementById("result-banner").style.display = "none";
  document.getElementById("ct-panel").style.display  = "none";
  document.getElementById("progress").style.width    = "0";
  document.getElementById("s-queries").textContent   = "0";
  document.getElementById("s-bytes").textContent     = "0/?";
  document.getElementById("s-block").textContent     = "—";
  document.getElementById("s-elapsed").textContent   = "0.0s";
  document.getElementById("avg-q").textContent       = "—";
  document.getElementById("max-q").textContent       = "—";
  document.getElementById("min-q").textContent       = "—";

  if (full) {
    document.getElementById("btn-start").disabled = false;
    document.getElementById("btn-stop").disabled  = true;
    setStatus("Ready — enter a plaintext and press Start Attack", "dim");
  }
}