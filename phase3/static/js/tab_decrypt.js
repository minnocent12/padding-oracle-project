// tab_decrypt.js — Decryption tab logic for Phase 3 GCM UI

// ── Pipeline helpers ──────────────────────────────────────────

function decPipeSet(id, state, statusText) {
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

function decPipeVal(id, html) {
  document.getElementById(id + "-val").innerHTML = html;
}

function decValBox(cls, label, value) {
  return `<div style="margin-top:.3rem">
    <div class="dim" style="font-size:.7rem;margin-bottom:2px">${label}</div>
    <div class="val-box ${cls}" style="font-size:.75rem">${value}</div>
  </div>`;
}

// ── Reset ─────────────────────────────────────────────────────

function resetDecrypt() {
  ["dec-s1","dec-s2","dec-s3","dec-s4","dec-s5"].forEach(id => {
    decPipeSet(id, "", "Waiting");
    decPipeVal(id, "");
  });
  document.getElementById("dec-result").style.display  = "none";
  document.getElementById("dec-tamper-note").style.display = "none";
  document.getElementById("btn-decrypt").disabled        = false;
  document.getElementById("btn-tamper-decrypt").disabled = false;
}

// ── Main decrypt ──────────────────────────────────────────────

async function runDecrypt(tamper) {
  const nonce = document.getElementById("dec-nonce").value.trim();
  const ct    = document.getElementById("dec-ct").value.trim();
  const tag   = document.getElementById("dec-tag").value.trim();

  if (!nonce || !ct || !tag) {
    alert("All three fields are required. Encrypt something first in the Encryption tab.");
    return;
  }

  resetDecrypt();
  document.getElementById("btn-decrypt").disabled        = true;
  document.getElementById("btn-tamper-decrypt").disabled = true;

  const delay = ms => new Promise(r => setTimeout(r, ms));

  // ── Optional: tamper the ciphertext ──────────────────────
  let sendCt = ct;
  if (tamper) {
    // Flip the last byte
    const lastByte  = parseInt(ct.slice(-2), 16);
    const flipped   = (255 - lastByte).toString(16).padStart(2, "0");
    sendCt          = ct.slice(0, -2) + flipped;
    const note      = document.getElementById("dec-tamper-note");
    note.style.display = "block";
    note.innerHTML  =
      `⚡ Tamper mode: last ciphertext byte flipped ` +
      `<span class="red">0x${ct.slice(-2)}</span> → ` +
      `<span class="green">0x${flipped}</span>`;
  }

  // ── Step 1: Receive values ────────────────────────────────
  decPipeSet("dec-s1", "active", "Receiving...");
  await delay(400);
  decPipeVal("dec-s1",
    decValBox("vb-green", "Nonce (hex)",      nonce) +
    decValBox("vb-blue",  "Ciphertext (hex)", sendCt +
      (tamper ? ` <span class="red">(tampered)</span>` : "")) +
    decValBox("vb-amber", "Auth Tag (hex)",   tag)
  );
  decPipeSet("dec-s1", "complete", "Done");
  await delay(300);

  // ── Step 2: Recompute GHASH tag ───────────────────────────
  decPipeSet("dec-s2", "active", "Computing GHASH...");
  await delay(500);
  decPipeVal("dec-s2",
    `<div class="val-box vb-dim" style="font-size:.75rem;margin-top:.3rem">
      GHASH(secret_key, received_ciphertext) → computing...
    </div>`
  );
  await delay(300);

  // ── Step 3: Compare tags — make the server call here ─────
  decPipeSet("dec-s3", "active", "Comparing tags...");
  await delay(400);

  let data, status;
  try {
    const r = await fetch("/decrypt", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ nonce, ciphertext: sendCt, tag })
    });
    status = r.status;
    data   = await r.json();
  } catch(e) {
    decPipeSet("dec-s3", "failed", "Error");
    document.getElementById("btn-decrypt").disabled        = false;
    document.getElementById("btn-tamper-decrypt").disabled = false;
    alert("Cannot reach GCM server: " + e.message);
    return;
  }

  // ── TAG MISMATCH path ─────────────────────────────────────
  if (status !== 200) {
    decPipeVal("dec-s2",
      decValBox("vb-dim", "Recomputed tag", "computed internally by server")
    );
    decPipeSet("dec-s2", "complete", "Done");

    decPipeVal("dec-s3",
      decValBox("vb-red", "Comparison result",
        "❌ Tags do not match — ciphertext was modified") +
      decValBox("vb-dim", "Action",
        "Request rejected immediately. Decryption never started.") +
      decValBox("vb-red", "Server response",
        `HTTP 403 — ${data.error}: ${data.reason}`) +
      decValBox("vb-dim", "Oracle signal", `${data.oracle} — no information leaked`)
    );
    decPipeSet("dec-s3", "failed", "Tag Mismatch");

    // Steps 4 and 5 never run
    decPipeSet("dec-s4", "failed", "Never reached");
    decPipeSet("dec-s5", "failed", "Never reached");
    decPipeVal("dec-s4",
      `<div class="val-box vb-red" style="font-size:.75rem;margin-top:.3rem">
        ✘ Decryption was not attempted — auth tag failed at Step 3.
      </div>`
    );
    decPipeVal("dec-s5",
      `<div class="val-box vb-red" style="font-size:.75rem;margin-top:.3rem">
        ✘ No plaintext returned — request rejected before decryption.
      </div>`
    );

    const banner   = document.getElementById("dec-result");
    banner.style.display = "block";
    banner.className     = "result-banner rb-fail";
    banner.innerHTML =
      `✘ Authentication Failed — ${tamper ? "tampered ciphertext detected" : "invalid tag"}<br/>
       <span style="font-size:.8rem;font-weight:normal">
         ${data.info || data.reason} · Oracle: ${data.oracle}
       </span>`;

    document.getElementById("btn-decrypt").disabled        = false;
    document.getElementById("btn-tamper-decrypt").disabled = false;
    return;
  }

  // ── TAG MATCH path ────────────────────────────────────────
  decPipeVal("dec-s2",
    decValBox("vb-green", "Recomputed tag", "computed internally — matches received tag")
  );
  decPipeSet("dec-s2", "complete", "Done");

  decPipeVal("dec-s3",
    decValBox("vb-green", "Comparison result",
      "✔ Tags match — ciphertext is authentic and unmodified") +
    decValBox("vb-dim",   "Comparison method", "Constant-time — no timing oracle possible") +
    decValBox("vb-dim",   "Action", "Proceeding to decryption...")
  );
  decPipeSet("dec-s3", "complete", "Tag Verified");
  await delay(300);

  // ── Step 4: Decrypt ───────────────────────────────────────
  decPipeSet("dec-s4", "active", "Decrypting...");
  await delay(400);
  decPipeVal("dec-s4",
    decValBox("vb-blue",  "Ciphertext (hex)",    data.ciphertext) +
    decValBox("vb-dim",   "Mode",                "AES-256 CTR — no padding to check") +
    decValBox("vb-purple","Plaintext (hex)",      data.plaintext_hex)
  );
  decPipeSet("dec-s4", "complete", "Done");
  await delay(300);

  // ── Step 5: Return result ─────────────────────────────────
  decPipeSet("dec-s5", "active", "Returning...");
  await delay(300);
  decPipeVal("dec-s5",
    decValBox("vb-green", "✔ Recovered Plaintext", data.plaintext) +
    decValBox("vb-dim",   "Tag verified",           String(data.tag_verified)) +
    decValBox("vb-dim",   "Tampered",               String(data.tampered))
  );
  decPipeSet("dec-s5", "complete", "Done");

  // ── Result banner ─────────────────────────────────────────
  const banner   = document.getElementById("dec-result");
  banner.style.display = "block";
  banner.className     = "result-banner rb-success";
  banner.textContent   =
    `✔ Decryption successful — Auth tag verified · Plaintext: "${data.plaintext}"`;

  document.getElementById("btn-decrypt").disabled        = false;
  document.getElementById("btn-tamper-decrypt").disabled = false;
}