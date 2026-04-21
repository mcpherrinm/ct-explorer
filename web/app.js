const form = document.querySelector("#lookup-form");
const targetInput = document.querySelector("#target");
const statusBand = document.querySelector("#status");
const certificateEl = document.querySelector("#certificate");
const validationEl = document.querySelector("#validation");
const sctsEl = document.querySelector("#scts");
const proofsEl = document.querySelector("#proofs");

const initialStatus = statusBand.textContent;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const target = targetInput.value.trim();
  if (!target) return;

  const currentParam = new URL(window.location.href).searchParams.get("url");
  if (target !== currentParam) {
    const next = new URL(window.location.href);
    next.searchParams.set("url", target);
    history.pushState({ target }, "", next);
  }
  runTrace(target);
});

window.addEventListener("popstate", () => {
  const target = new URL(window.location.href).searchParams.get("url");
  if (target) {
    targetInput.value = target;
    runTrace(target);
  } else {
    resetReport();
  }
});

const initialTarget = new URL(window.location.href).searchParams.get("url");
if (initialTarget) {
  targetInput.value = initialTarget;
  runTrace(initialTarget);
}

async function runTrace(target) {
  setStatus(`Tracing ${target}...`);
  setLoading();

  try {
    const response = await fetch(`/api/analyze?url=${encodeURIComponent(target)}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Request failed");
    }
    renderReport(payload);
  } catch (error) {
    setStatus(error.message);
    certificateEl.className = "empty";
    certificateEl.textContent = "The trace did not complete.";
    validationEl.className = "empty";
    validationEl.textContent = "";
    sctsEl.className = "empty";
    sctsEl.textContent = "";
    proofsEl.className = "empty";
    proofsEl.textContent = "";
  }
}

function resetReport() {
  setStatus(initialStatus);
  certificateEl.className = "empty";
  certificateEl.textContent = "";
  validationEl.className = "empty";
  validationEl.textContent = "";
  sctsEl.className = "empty";
  sctsEl.textContent = "";
  proofsEl.className = "empty";
  proofsEl.textContent = "";
}

function setLoading() {
  certificateEl.className = "empty";
  validationEl.className = "empty";
  sctsEl.className = "empty";
  proofsEl.className = "empty";
  certificateEl.textContent = "Opening a TLS connection and reading the leaf certificate.";
  validationEl.textContent = "Checking hostname and chain validation.";
  sctsEl.textContent = "Decoding SCTs from the certificate and TLS handshake.";
  proofsEl.textContent = "Matching SCT log IDs against the public log directory.";
}

function renderReport(report) {
  const cert = report.certificate;
  setStatus(`Fetched ${report.target.server} at ${formatDate(report.target.fetched)}. Found ${report.scts.length} SCT${report.scts.length === 1 ? "" : "s"}.`);

  renderCertificateSummary(report);

  validationEl.className = "facts";
  validationEl.innerHTML = `
    <div class="badge-row">
      <span class="badge ${report.validation.hostname_ok ? "good" : "bad"}">${report.validation.hostname_ok ? "✓ hostname matches" : "hostname failed"}</span>
      <span class="badge ${report.validation.chain_ok ? "good" : "bad"}">${report.validation.chain_ok ? "✓ certificate is trusted" : "certificate is not trusted"}</span>
    </div>
    ${report.validation.hostname_error ? fact("Hostname error", report.validation.hostname_error) : ""}
    ${report.validation.chain_error ? fact("Chain error", report.validation.chain_error) : ""}
  `;

  renderSCTs(report.scts);
  renderProofs(report);
}

function renderCertificateSummary(report) {
  const cert = report.certificate;
  const embeddedCount = cert.embedded_sct_count || 0;
  const tlsCount = cert.tls_sct_count || 0;
  const delivery = [
    embeddedCount ? "certificate extension" : "",
    tlsCount ? "TLS handshake" : "",
  ].filter(Boolean).join(" + ") || "No SCTs delivered";

  certificateEl.className = "facts cert-summary";
  certificateEl.innerHTML = [
    factGroup("Identity", [
      fact("Subject", cert.subject),
      fact("Issuer", cert.issuer),
      fact("Serial", cert.serial_number),
      fact("Names", (cert.dns_names || []).slice(0, 12).join(", ") || "No DNS names in certificate"),
    ]),
    factGroup("Validity", [
      fact("Valid From", formatDate(cert.not_before)),
      fact("Valid Until", formatDate(cert.not_after)),
      fact("Signature", cert.signature_algo),
      fact("Public Key", cert.public_key_algo),
    ]),
    factGroup("Fingerprints", [
      fact("Certificate SHA-256", cert.sha256),
      fact("TBS SHA-256", cert.tbs_sha256),
      fact("SPKI SHA-256", cert.spki_sha256),
    ]),
    factGroup("Certificate Transparency", [
      fact("SCT Extension", cert.embedded_sct_extension_present ? "present" : "missing"),
      fact("Embedded SCTs", String(embeddedCount)),
      fact("TLS SCTs", String(tlsCount)),
      fact("Delivery", delivery),
    ]),
  ].join("");
}

function renderSCTs(scts) {
  if (!scts.length) {
    sctsEl.className = "empty";
    sctsEl.textContent = "No SCT was found in the certificate or TLS handshake.";
    return;
  }

  sctsEl.className = "sct-grid";
  sctsEl.innerHTML = scts.map((sct, index) => {
    const logName = sct.log?.description || "Unknown log";
    const operator = sct.log?.operator || "No matching public log entry";
    const state = sct.log?.state;
    return `
      <article class="sct-card">
        <h3>${escapeHTML(logName)}</h3>
        ${renderLogStatePill(state)}
        <p class="mini">promise ${index + 1} / ${escapeHTML(operator)}</p>
        <p class="mini">source: ${escapeHTML(sct.source)}</p>
        <p class="mini">timestamp: ${formatDate(sct.timestamp)}</p>
        <p class="mini">signature: ${escapeHTML(sct.hash_alg)} + ${escapeHTML(sct.signature_alg)}</p>
        <p class="mini">log id: ${escapeHTML(sct.log_id)}</p>
        ${sct.log?.type ? `<p class="mini">api: ${escapeHTML(apiLabel(sct.log.type))}</p>` : ""}
      </article>
    `;
  }).join("");
}

function apiLabel(type) {
  if (type === "static-ct-api") return "Static CT API (tiles + checkpoint)";
  if (type === "rfc6962") return "RFC 6962 (get-sth + get-proof-by-hash)";
  return type;
}

function renderLogStatePill(state) {
  if (!state) return "";
  const usable = state === "usable";
  const cls = usable ? "state-pill state-pill-usable" : "state-pill state-pill-flag";
  const prefix = usable ? "" : "⚠ not usable · ";
  return `<p class="state-row"><span class="${cls}">${escapeHTML(prefix + state)}</span></p>`;
}

function renderProofs(report) {
  const notes = (report.proof_notes || []).map((note) => `<p class="proof-note">${escapeHTML(note)}</p>`).join("");
  const proofCards = report.scts.map((sct) => {
    const proof = sct.proof || { status: "not-attempted", explanation: "no proof attempt was available" };
    const proven = proof.status === "proven-x509-leaf" || proof.status === "proven-precert-leaf";
    const rootText = proof.root_ok ? "STH root verified" : "STH root not verified";
    const flavor = proof.api_flavor || sct.log?.type;
    return `
      <article class="proof-item ${proven ? "proven" : ""}">
        <h3>${escapeHTML(sct.log?.description || "Unknown log")}</h3>
        <div class="badge-row">
          <span class="badge ${proven ? "good" : "bad"}">${proven ? "✓ inclusion proven" : "proof missing"}</span>
          ${proof.tree_size ? `<span class="badge ${proof.root_ok ? "good" : "bad"}">${proof.root_ok ? `✓ ${rootText}` : rootText}</span>` : ""}
          ${flavor ? `<span class="badge">${escapeHTML(apiLabel(flavor))}</span>` : ""}
        </div>
        <p>${escapeHTML(proof.explanation)}</p>
        ${renderStaticCTBlock(proof)}
        ${renderMerklePath(proof)}
        ${renderHashTranscript(proof)}
        ${proof.leaf_hash ? `<p class="mini">leaf hash ${escapeHTML(proof.leaf_hash)}</p>` : ""}
        ${proof.tree_size ? `<p class="mini">tree size ${proof.tree_size} · leaf index ${proof.leaf_index}${proof.leaf_index_from_sct ? " (from SCT leaf_index extension)" : ""}</p>` : ""}
        ${proof.audit_path?.length ? `<p class="mini">audit path nodes ${proof.audit_path.length}</p>` : ""}
        ${proof.proof_url ? `<p class="mini"><a class="plain-link" href="${escapeHTML(proof.proof_url)}" target="_blank" rel="noopener noreferrer">${proof.api_flavor === "static-ct-api" ? "View raw checkpoint" : "View raw inclusion proof"}</a></p>` : ""}
      </article>
    `;
  }).join("");

  proofsEl.className = "proof-list";
  proofsEl.innerHTML = notes + (proofCards || `<div class="empty">There were no SCTs to match against logs.</div>`);
}

function renderStaticCTBlock(proof) {
  if (proof.api_flavor !== "static-ct-api") return "";
  const rows = [];
  if (proof.checkpoint_origin) {
    rows.push(`<p class="mini">checkpoint origin: ${escapeHTML(proof.checkpoint_origin)}</p>`);
  }
  if (proof.checkpoint_body) {
    rows.push(`<details class="hash-transcript"><summary>Show signed checkpoint body</summary><pre class="checkpoint-body"><code>${escapeHTML(proof.checkpoint_body)}</code></pre></details>`);
  }
  if (proof.tile_urls?.length) {
    const links = proof.tile_urls.map((u) => `<li><a class="plain-link" href="${escapeHTML(u)}" target="_blank" rel="noopener noreferrer">${escapeHTML(u)}</a></li>`).join("");
    rows.push(`<details class="hash-transcript"><summary>Show ${proof.tile_urls.length} tile${proof.tile_urls.length === 1 ? "" : "s"} fetched to rebuild the audit path</summary><ul class="tile-list">${links}</ul></details>`);
  }
  return rows.join("");
}

function renderMerklePath(proof) {
  if (!proof.audit_steps?.length || !proof.leaf_hash) {
    return "";
  }

  const tileLevels = tileLevelsForSteps(proof);
  const stepsFromRoot = proof.audit_steps.slice().reverse();
  const leaf = shortHash(proof.leaf_hash);
  const root = shortHash(proof.tree_head || "");
  const mobileSteps = proof.audit_steps.map((step, index) => {
    const currentHash = index === 0 ? proof.leaf_hash : proof.audit_steps[index - 1].parent_hash;
    const tileDivider = tileBoundaryDivider(tileLevels, index, index - 1);
    return `
      ${tileDivider}
      <li class="${tileLevelClass(tileLevels, index)}">
        <div class="audit-step-title">
          <b>L${step.level + 1}</b>
          <span>${escapeHTML(step.sibling_side)} sibling</span>
        </div>
        <dl>
          <dt>Current</dt>
          <dd>${escapeHTML(shortHash(currentHash))}</dd>
          <dt>Sibling</dt>
          <dd>${escapeHTML(shortHash(step.sibling_hash))}</dd>
          <dt>Parent</dt>
          <dd>${escapeHTML(shortHash(step.parent_hash))}</dd>
        </dl>
      </li>
    `;
  }).join("");

  const desktopRows = stepsFromRoot.map((step, iRev) => {
    const iOrig = proof.audit_steps.length - 1 - iRev;
    const prevIOrig = iRev === 0 ? -1 : proof.audit_steps.length - iRev;
    const tileDivider = tileBoundaryDivider(tileLevels, iOrig, prevIOrig);
    return `
      ${tileDivider}
      <div class="tree-row branch-${step.sibling_side} ${tileLevelClass(tileLevels, iOrig)}">
        <div class="tree-cell left-cell">
          ${step.sibling_side === "left" ? treeSibling(step) : ""}
        </div>
        <div class="tree-spine">
          <div class="tree-node path-node">
            <b>L${step.level + 1} parent</b>
            <span>${escapeHTML(shortHash(step.parent_hash))}</span>
          </div>
        </div>
        <div class="tree-cell right-cell">
          ${step.sibling_side === "right" ? treeSibling(step) : ""}
        </div>
      </div>
    `;
  }).join("");

  return `
    <div class="merkle-tree" aria-label="Verified Merkle audit path as a tree">
      <div class="tree-caption">
        ${proof.audit_steps.length} SHA-256 sibling hashes rebuild one path through the Merkle tree.${tileLevels ? " Tile boundaries are marked where one Static CT tile's hashes end and the next begins." : ""}
      </div>
      <div class="tree-root tree-node">
        <b>STH root</b>
        <span>${escapeHTML(root)}</span>
      </div>
      <div class="tree-scroll">
        ${desktopRows}
      </div>
      <div class="tree-leaf tree-node">
        <b>certificate leaf</b>
        <span>${escapeHTML(leaf)}</span>
      </div>
      <div class="audit-timeline">
        <div class="audit-endpoint">
          <b>Leaf</b>
          <span>${escapeHTML(leaf)}</span>
        </div>
        <ol>${mobileSteps}</ol>
        <div class="audit-endpoint verified">
          <b>STH root</b>
          <span>${escapeHTML(root)}</span>
        </div>
      </div>
    </div>
  `;
}

function treeSibling(step) {
  return `
    <div class="tree-node sibling-node">
      <b>${escapeHTML(step.sibling_side)} sibling</b>
      <span>${escapeHTML(shortHash(step.sibling_hash))}</span>
    </div>
  `;
}

function tileLevelsForSteps(proof) {
  if (proof.api_flavor !== "static-ct-api") return null;
  if (!proof.audit_steps?.length) return null;
  const treeSize = Number(proof.tree_size);
  const leafIndex = Number(proof.leaf_index);
  if (!Number.isFinite(treeSize) || treeSize < 1) return null;
  if (!Number.isFinite(leafIndex) || leafIndex < 0) return null;

  const levels = [];
  let sn = leafIndex;
  let fn = treeSize - 1;
  let merkleLevel = 0;
  while (fn > 0) {
    const skip = sn === fn && sn % 2 === 0;
    if (!skip) {
      levels.push(Math.floor(merkleLevel / 8));
    }
    sn = Math.floor(sn / 2);
    fn = Math.floor(fn / 2);
    merkleLevel++;
  }
  if (levels.length !== proof.audit_steps.length) return null;
  return levels;
}

function tileLevelClass(tileLevels, originalIndex) {
  if (!tileLevels) return "";
  const lvl = tileLevels[originalIndex];
  if (lvl === undefined) return "";
  return `tile-level-${lvl}`;
}

// tileBoundaryDivider returns a divider node when the tile level at `currentIndex`
// differs from the tile level at `prevIndex` (using the original, leaf-to-root
// audit-path indexing). Returns "" when tile info is unavailable or no boundary
// crossing happens.
function tileBoundaryDivider(tileLevels, currentIndex, prevIndex) {
  if (!tileLevels) return "";
  const current = tileLevels[currentIndex];
  if (current === undefined) return "";
  const prev = prevIndex >= 0 && prevIndex < tileLevels.length ? tileLevels[prevIndex] : null;
  if (prev === current) return "";
  return `<div class="tile-divider" role="presentation"><span>Level ${current} tile</span></div>`;
}

function renderHashTranscript(proof) {
  if (!proof.audit_steps?.length || !proof.leaf_hash) {
    return "";
  }

  const mobileRows = [];
  const rows = proof.audit_steps.map((step, index) => {
    const currentHash = index === 0 ? proof.leaf_hash : proof.audit_steps[index - 1].parent_hash;
    const left = step.sibling_side === "left" ? step.sibling_hash : currentHash;
    const right = step.sibling_side === "right" ? step.sibling_hash : currentHash;
    mobileRows.push(`
      <section class="transcript-card">
        <h4>L${step.level + 1}</h4>
        <dl>
          <dt>Left input</dt>
          <dd><code>${escapeHTML(left)}</code></dd>
          <dt>Right input</dt>
          <dd><code>${escapeHTML(right)}</code></dd>
          <dt>SHA-256 parent</dt>
          <dd><code>${escapeHTML(step.parent_hash)}</code></dd>
        </dl>
      </section>
    `);
    return `
      <tr>
        <td>L${step.level + 1}</td>
        <td>${escapeHTML(left)}</td>
        <td>${escapeHTML(right)}</td>
        <td>${escapeHTML(step.parent_hash)}</td>
      </tr>
    `;
  }).join("");

  return `
    <details class="hash-transcript">
      <summary>Show every SHA-256 hash from leaf to STH root</summary>
      <div class="transcript-copy">
        Start with the reconstructed CT leaf hash, combine each SHA-256 sibling in left/right order, and compare the final parent to the Signed Tree Head root.
      </div>
      <div class="root-check">
        <b>Leaf</b>
        <code>${escapeHTML(proof.leaf_hash)}</code>
        <b>Final parent</b>
        <code>${escapeHTML(proof.audit_steps.at(-1).parent_hash)}</code>
        <b>STH root</b>
        <code>${escapeHTML(proof.tree_head || "")}</code>
      </div>
      <div class="transcript-table-wrap">
        <table class="transcript-table">
          <thead>
            <tr>
              <th>Level</th>
              <th>Left input</th>
              <th>Right input</th>
              <th>SHA-256 parent</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="transcript-cards">${mobileRows.join("")}</div>
    </details>
  `;
}

function fact(label, value) {
  return `<div class="fact"><b>${escapeHTML(label)}</b><span>${escapeHTML(value || "—")}</span></div>`;
}

function factGroup(title, rows) {
  return `
    <section class="fact-group">
      <h3>${escapeHTML(title)}</h3>
      ${rows.join("")}
    </section>
  `;
}

function setStatus(message) {
  statusBand.textContent = message;
}

function formatDate(value) {
  if (!value) return "unknown";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function shortHash(value) {
  const text = String(value || "");
  if (text.length <= 20) return text;
  return `${text.slice(0, 11)}...${text.slice(-7)}`;
}
