// tab_encrypt.js — Encryption tab logic for Phase 3 GCM UI

// ── Pipeline helpers ──────────────────────────────────────────

function pipeSet(id, state, statusText) {
  const el  = document.getElementById(id);
  const sts = document.getElementById(id + "-status");
  el.className  = "pipe-step " + state;
  sts.className = "pipe-status ps-" + (
    state === "active"   ? "running" :
    state === "complete" ? "done"    :
    state === "failed"   ? "failed"  : "waiting"
  );
  sts.textContent = statusText;
}

function pipeVal(id, html) {
  document.getElementById(id + "-val").innerHTML = html;
}

function valBox(cls, label, value) {
  return `<div style="margin-top:.3rem">
    <div class="dim" style="font-size:.7rem;margin-bottom:2px">${label}</div>
    <div class="val-box ${cls}" style="font-size:.75rem">${value}</div>
  </div>`;
}

// ── Reset ─────────────────────────────────────────────────────

function resetEncrypt() {
  ["enc-s1","enc-s2","enc-s3","enc-s4","enc-s5"].forEach(id => {
    pipeSet(id, "", "Waiting");
    pipeVal(id, "");
  });
  document.getElementById("enc-result").style.display   = "none";
  document.getElementById("enc-summary").style.display  = "none";
  document.getElementById("btn-encrypt").disabled       = false;
}

// ── Main encrypt ──────────────────────────────────────────────

async function runEncrypt() {
  const pt = document.getElementById("enc-pt").value.trim();
  if (!pt) { alert("Enter a plaintext message."); return; }

  resetEncrypt();
  document.getElementById("btn-encrypt").disabled = true;

  const delay = ms => new Promise(r => setTimeout(r, ms));

  // ── Step 1: Read plaintext ────────────────────────────────
  pipeSet("enc-s1", "active", "Running...");
  await delay(400);
  const ptHex   = Array.from(new TextEncoder().encode(pt))
                       .map(b => b.toString(16).padStart(2,"0")).join(" ");
  const ptBytes = new TextEncoder().encode(pt).length;
  pipeVal("enc-s1",
    valBox("vb-dim",   "Plaintext (text)",        pt) +
    valBox("vb-purple","Plaintext (hex bytes)",    ptHex) +
    valBox("vb-dim",   "Length",                  `${ptBytes} bytes`)
  );
  pipeSet("enc-s1", "complete", "Done");
  await delay(300);

  // ── Step 2: Generate nonce (show spinner then result) ─────
  pipeSet("enc-s2", "active", "Generating...");
  await delay(500);

  // ── Step 3: Encrypt (server call) ────────────────────────
  pipeSet("enc-s3", "active", "Encrypting...");

  let data;
  try {
    const r = await fetch("/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ plaintext: pt })
    });
    data = await r.json();
    if (!r.ok) throw new Error(data.error || "Encryption failed");
  } catch(e) {
    pipeSet("enc-s2", "failed", "Failed");
    pipeSet("enc-s3", "failed", "Failed");
    document.getElementById("btn-encrypt").disabled = false;
    alert("Cannot reach GCM server: " + e.message);
    return;
  }

  // Fill step 2 now we have the nonce
  pipeVal("enc-s2",
    valBox("vb-green", "Nonce (hex)",  data.nonce) +
    valBox("vb-dim",   "Nonce size",   `${data.nonce_bits} bits — random, unique per message`)
  );
  pipeSet("enc-s2", "complete", "Done");
  await delay(300);

  // Fill step 3
  pipeVal("enc-s3",
    valBox("vb-blue", "Ciphertext (hex)",        data.ciphertext) +
    valBox("vb-dim",  "Ciphertext size",          `${data.ciphertext_bytes} bytes`) +
    valBox("vb-dim",  "Mode",                     "AES-256 CTR — no padding needed")
  );
  pipeSet("enc-s3", "complete", "Done");
  await delay(300);

  // ── Step 4: Auth tag ──────────────────────────────────────
  pipeSet("enc-s4", "active", "Computing tag...");
  await delay(400);
  pipeVal("enc-s4",
    valBox("vb-amber", "Auth Tag (hex)",  data.tag) +
    valBox("vb-dim",   "Tag size",        `${data.tag_bits} bits`) +
    valBox("vb-dim",   "Function",        "GHASH(key, ciphertext) — integrity proof")
  );
  pipeSet("enc-s4", "complete", "Done");
  await delay(300);

  // ── Step 5: Output ────────────────────────────────────────
  pipeSet("enc-s5", "active", "Packaging...");
  await delay(300);
  pipeVal("enc-s5",
    valBox("vb-green", "Nonce",      data.nonce) +
    valBox("vb-blue",  "Ciphertext", data.ciphertext) +
    valBox("vb-amber", "Auth Tag",   data.tag)
  );
  pipeSet("enc-s5", "complete", "Done");

  // ── Result banner ─────────────────────────────────────────
  const banner = document.getElementById("enc-result");
  banner.style.display = "block";
  banner.className     = "result-banner rb-success";
  banner.textContent   =
    `✔ Encryption successful — "${pt}" → ${data.ciphertext_bytes} bytes ciphertext + 128-bit auth tag`;

  // ── Summary panel ─────────────────────────────────────────
  document.getElementById("sum-nonce").textContent = data.nonce;
  document.getElementById("sum-ct").textContent    = data.ciphertext;
  document.getElementById("sum-tag").textContent   = data.tag;
  document.getElementById("enc-summary").style.display = "block";

  // ── Auto-fill decryption tab ──────────────────────────────
  const dn = document.getElementById("dec-nonce");
  const dc = document.getElementById("dec-ct");
  const dt = document.getElementById("dec-tag");
  if (dn) dn.value = data.nonce;
  if (dc) dc.value = data.ciphertext;
  if (dt) dt.value = data.tag;

  document.getElementById("btn-encrypt").disabled = false;
}