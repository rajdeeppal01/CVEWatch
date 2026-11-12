/**
 * app.js — CVEWatch dashboard logic.
 * Handles: CVE table rendering, filters, pagination,
 *          detail modal, SSE live updates, stats bar.
 */

const API = "";  // same origin — backend serves frontend

// ── State ────────────────────────────────────────────────────────
let currentPage   = 0;
let currentLimit  = 50;
let currentTotal  = 0;
let searchTimeout = null;
let sseSource     = null;

// ── Init ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadStats();
  loadCVEs();
  connectSSE();
});

// ── SSE Live Updates ─────────────────────────────────────────────
function connectSSE() {
  if (sseSource) sseSource.close();

  sseSource = new EventSource(`${API}/api/stream`);

  sseSource.addEventListener("connected", () => {
    setLive(true);
    updateLastUpdated("Live stream connected");
  });

  sseSource.addEventListener("refresh", (e) => {
    const data = JSON.parse(e.data);
    showToast(
      `↻ Refreshed: ${data.new} new CVEs, ${data.updated} updated`,
      "success"
    );
    loadStats();
    loadCVEs();
    updateLastUpdated(new Date().toLocaleTimeString());
  });

  sseSource.addEventListener("initial_fetch", (e) => {
    const data = JSON.parse(e.data);
    showToast(`Initial fetch complete: ${data.new} CVEs loaded`, "success");
    loadStats();
    loadCVEs();
  });

  sseSource.addEventListener("heartbeat", () => {
    setLive(true);
  });

  sseSource.onerror = () => {
    setLive(false);
    updateLastUpdated("Reconnecting...");
    // Auto-reconnect after 5s
    setTimeout(connectSSE, 5000);
  };
}

function setLive(live) {
  const el = document.getElementById("liveIndicator");
  if (live) {
    el.classList.remove("disconnected");
  } else {
    el.classList.add("disconnected");
  }
}

function updateLastUpdated(text) {
  document.getElementById("lastUpdated").textContent = text;
}

// ── Stats Bar ────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch(`${API}/api/stats`);
    if (!res.ok) return;
    const s = await res.json();

    document.getElementById("statCritical").textContent = s.critical?.toLocaleString() ?? "—";
    document.getElementById("statHigh").textContent     = s.high?.toLocaleString()     ?? "—";
    document.getElementById("statMedium").textContent   = s.medium?.toLocaleString()   ?? "—";
    document.getElementById("statLow").textContent      = s.low?.toLocaleString()      ?? "—";
    document.getElementById("statTotal").textContent    = s.total?.toLocaleString()    ?? "—";
    document.getElementById("statPatched").textContent  = s.patched?.toLocaleString()  ?? "—";

    if (s.last_fetch) {
      const d = new Date(s.last_fetch.at);
      updateLastUpdated(`Last fetch: ${d.toLocaleString()}`);
    }
  } catch (e) {
    console.error("Stats load failed:", e);
  }
}

// ── CVE Table ────────────────────────────────────────────────────
async function loadCVEs(resetPage = true) {
  if (resetPage) currentPage = 0;

  const severity  = document.getElementById("filterSeverity").value;
  const sortBy    = document.getElementById("filterSort").value;
  const search    = document.getElementById("searchInput").value.trim();
  currentLimit    = parseInt(document.getElementById("filterLimit").value);
  const offset    = currentPage * currentLimit;

  const params = new URLSearchParams({
    severity,
    sort_by:    sortBy,
    sort_order: "desc",
    limit:      currentLimit,
    offset,
  });
  if (search) params.append("search", search);

  const tbody = document.getElementById("cveTableBody");
  tbody.innerHTML = `<tr><td colspan="8" class="loading-row">Loading...</td></tr>`;

  try {
    const res = await fetch(`${API}/api/cves?${params}`);
    if (!res.ok) throw new Error(res.statusText);
    const { cves, count } = await res.json();

    currentTotal = count;
    renderTable(cves);
    updatePagination(count);
    document.getElementById("tableCount").textContent =
      `Showing ${offset + 1}–${offset + count} CVEs`;

  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="loading-row" style="color:var(--critical)">
      Failed to load CVEs: ${e.message}</td></tr>`;
  }
}

function renderTable(cves) {
  const tbody = document.getElementById("cveTableBody");

  if (!cves.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="loading-row">No CVEs match your filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = cves.map(cve => {
    const scoreClass = cvssClass(cve.cvss_score);
    const dateShort  = cve.published ? cve.published.slice(0, 10) : "—";
    const vendor     = [cve.vendor, cve.product].filter(Boolean).join(" / ") || "—";
    const summary    = truncate(cve.description, 90);
    const patchIcon  = cve.patch_available ? `<span class="patch-yes" title="Patch available">✓</span>`
                                           : `<span class="patch-no"  title="No patch">—</span>`;

    return `
      <tr onclick="openModal('${escHtml(cve.cve_id)}')">
        <td class="cve-id-cell">${escHtml(cve.cve_id)}</td>
        <td><span class="badge badge-${cve.severity || 'UNKNOWN'}">${cve.severity || 'N/A'}</span></td>
        <td class="cvss-score ${scoreClass}">${cve.cvss_score ?? '—'}</td>
        <td class="vendor-cell">${escHtml(vendor)}</td>
        <td class="date-cell">${dateShort}</td>
        <td style="text-align:center">${patchIcon}</td>
        <td class="summary-cell" title="${escHtml(cve.description)}">${escHtml(summary)}</td>
        <td onclick="event.stopPropagation()">
          <button class="btn-detail" onclick="openModal('${escHtml(cve.cve_id)}')">Details</button>
        </td>
      </tr>`;
  }).join("");
}

function updatePagination(count) {
  const totalPages = Math.ceil(currentTotal / currentLimit) || 1;
  document.getElementById("pageInfo").textContent   = `Page ${currentPage + 1}`;
  document.getElementById("btnPrev").disabled       = currentPage === 0;
  document.getElementById("btnNext").disabled       = count < currentLimit;
}

function prevPage() {
  if (currentPage > 0) { currentPage--; loadCVEs(false); }
}

function nextPage() {
  currentPage++;
  loadCVEs(false);
}

// ── Search Debounce ──────────────────────────────────────────────
function debounceSearch() {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => loadCVEs(), 400);
}

// ── Refresh Button ───────────────────────────────────────────────
async function triggerRefresh() {
  const btn = document.getElementById("btnRefresh");
  btn.disabled = true;
  btn.textContent = "↻ Refreshing...";
  btn.classList.add("spinning");

  try {
    const res = await fetch(`${API}/api/refresh`, { method: "POST" });
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    showToast(`Refresh done: ${data.new} new, ${data.updated} updated`, "success");
    loadStats();
    loadCVEs();
  } catch (e) {
    showToast(`Refresh failed: ${e.message}`, "error");
  } finally {
    btn.disabled    = false;
    btn.textContent = "↻ Refresh Now";
    btn.classList.remove("spinning");
  }
}

// ── Detail Modal ─────────────────────────────────────────────────
async function openModal(cveId) {
  try {
    const res = await fetch(`${API}/api/cves/${encodeURIComponent(cveId)}`);
    if (!res.ok) throw new Error("CVE not found");
    const cve = await res.json();

    document.getElementById("modalCveId").textContent      = cve.cve_id;
    document.getElementById("modalSeverity").textContent   = cve.severity || "UNKNOWN";
    document.getElementById("modalSeverity").className     = `badge badge-${cve.severity || 'UNKNOWN'}`;
    document.getElementById("modalScore").textContent      = cve.cvss_score ? `${cve.cvss_score} / 10` : "N/A";
    document.getElementById("modalScore").className        = `modal-score cvss-score ${cvssClass(cve.cvss_score)}`;
    document.getElementById("modalDescription").textContent = cve.description || "No description available.";
    document.getElementById("modalVendor").textContent     = cve.vendor    || "—";
    document.getElementById("modalProduct").textContent    = cve.product   || "—";
    document.getElementById("modalVersions").textContent   = cve.affected_versions || "—";
    document.getElementById("modalCwe").textContent        = cve.cwe       || "—";
    document.getElementById("modalPublished").textContent  = formatDate(cve.published);
    document.getElementById("modalModified").textContent   = formatDate(cve.modified);
    document.getElementById("modalVector").textContent     = cve.cvss_vector || "—";
    document.getElementById("modalPatch").textContent      = cve.patch_available ? "✅ Yes" : "❌ Not confirmed";

    // Remediation steps — split on " | "
    const remEl = document.getElementById("modalRemediation");
    const steps = (cve.remediation || "Review vendor advisory.").split(" | ");
    remEl.innerHTML = steps.map(s =>
      `<div class="remediation-step">${escHtml(s)}</div>`
    ).join("");

    // References
    const refsEl = document.getElementById("modalRefs");
    const refs   = (cve.references || "").split(" | ").filter(Boolean);
    if (refs.length) {
      refsEl.innerHTML = refs.map(r =>
        `<a href="${escHtml(r)}" target="_blank" rel="noopener noreferrer">${escHtml(r)}</a>`
      ).join("");
    } else {
      refsEl.innerHTML = `<span style="color:var(--text-muted)">No references available.</span>`;
    }

    document.getElementById("modalOverlay").classList.add("open");
    document.body.style.overflow = "hidden";

  } catch (e) {
    showToast(`Failed to load CVE details: ${e.message}`, "error");
  }
}

function closeModal() {
  document.getElementById("modalOverlay").classList.remove("open");
  document.body.style.overflow = "";
}

// Close on Escape
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

// ── Toast Notifications ──────────────────────────────────────────
function showToast(message, type = "info", duration = 4000) {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.4s";
    setTimeout(() => toast.remove(), 400);
  }, duration);
}

// ── Helpers ──────────────────────────────────────────────────────
function cvssClass(score) {
  if (score === null || score === undefined) return "cvss-na";
  if (score >= 9.0) return "cvss-critical";
  if (score >= 7.0) return "cvss-high";
  if (score >= 4.0) return "cvss-medium";
  return "cvss-low";
}

function truncate(str, len) {
  if (!str) return "";
  return str.length > len ? str.slice(0, len) + "…" : str;
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
