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
    const severity   = cve.severity || "UNKNOWN";
    const badgeLabel = severity === "UNKNOWN" ? "PENDING" : severity;

    return `
      <tr onclick="openModal('${escHtml(cve.cve_id)}')">
        <td class="cve-id-cell">${escHtml(cve.cve_id)}</td>
        <td><span class="badge badge-${severity}">${badgeLabel}</span></td>
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


// ── Tab Switching ────────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

  const tabId   = `tab${tab.charAt(0).toUpperCase() + tab.slice(1)}`;
  const panelId = `panel${tab.charAt(0).toUpperCase() + tab.slice(1)}`;
  document.getElementById(tabId).classList.add("active");
  document.getElementById(panelId).classList.add("active");

  // Android tab: auto-detect on first open, load history
  if (tab === "android") {
    detectDevice();
    loadScanHistory();
  }
  // CVE tab: re-render stats in case they updated while on Android tab
  if (tab === "cve") {
    loadStats();
  }
}

// ── Android Scanner State ────────────────────────────────────────
let currentScanReport = null;
let allVulnerabilities = [];

// ── Detect Device ────────────────────────────────────────────────
async function detectDevice() {
  const btn = document.getElementById("btnDetect");
  btn.disabled = true;
  btn.textContent = "🔍 Detecting...";

  try {
    const res = await fetch(`${API}/api/android/status`);
    const data = await res.json();

    document.getElementById("adbInstructions").style.display = "none";

    if (!data.adb_available) {
      setDeviceStatus("error", "ADB Not Found");
      document.getElementById("deviceName").textContent = "ADB not installed";
      document.getElementById("deviceMeta").textContent = data.error;
      document.getElementById("adbInstructions").style.display = "block";
      document.getElementById("btnScan").disabled = true;
      return;
    }

    const online = data.devices.filter(d => d.state === "device");

    if (online.length === 0) {
      setDeviceStatus("waiting", "No Device");
      document.getElementById("deviceName").textContent = "No device connected";
      document.getElementById("deviceMeta").textContent =
        "Connect your Android phone via USB with USB Debugging enabled, then click Detect again.";
      document.getElementById("btnScan").disabled = true;
      return;
    }

    const dev = online[0];
    setDeviceStatus("connected", "Connected");
    document.getElementById("deviceName").textContent =
      dev.model || dev.serial;
    document.getElementById("deviceMeta").textContent =
      `Serial: ${dev.serial}` + (online.length > 1 ? ` (+${online.length - 1} more)` : "");
    document.getElementById("btnScan").disabled = false;

    showToast(`Device detected: ${dev.model || dev.serial}`, "success");

  } catch (e) {
    setDeviceStatus("error", "Error");
    document.getElementById("deviceName").textContent = "Detection failed";
    document.getElementById("deviceMeta").textContent = e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "🔍 Detect Device";
  }
}

function setDeviceStatus(type, text) {
  const pill = document.getElementById("deviceStatusPill");
  pill.className = `device-status-pill ${type}`;
  document.getElementById("deviceStatusText").textContent = text;
}

// ── Start Scan ───────────────────────────────────────────────────
async function startScan() {
  const btnScan = document.getElementById("btnScan");
  btnScan.disabled = true;

  // Hide results, show progress
  document.getElementById("scanResults").style.display  = "none";
  document.getElementById("scanHistory").style.display  = "none";
  document.getElementById("scanProgress").style.display = "block";

  setDeviceStatus("scanning", "Scanning...");
  setProgressStep(1);

  // Animate steps while waiting (the scan can take 30–60s)
  const stepTimers = [
    setTimeout(() => setProgressStep(2), 3000),
    setTimeout(() => setProgressStep(3), 8000),
    setTimeout(() => setProgressStep(4), 15000),
  ];

  try {
    const res = await fetch(`${API}/api/android/scan`, { method: "POST" });
    stepTimers.forEach(t => clearTimeout(t));
    setProgressStep(4, true); // mark all done

    const report = await res.json();
    document.getElementById("scanProgress").style.display = "none";

    if (report.status !== "ok") {
      setDeviceStatus("error", "Failed");
      showToast(`Scan failed: ${report.error}`, "error");

      // If multiple devices, show selection
      if (report.status === "multiple_devices") {
        showToast("Multiple devices connected — only one at a time is supported currently.", "warning");
      }
      btnScan.disabled = false;
      return;
    }

    currentScanReport = report;
    allVulnerabilities = report.vulnerabilities || [];
    renderScanReport(report);
    setDeviceStatus("done", "Scan Complete");
    showToast(`Scan complete: ${report.total_vulnerabilities} vulnerabilities found`, "success");

  } catch (e) {
    stepTimers.forEach(t => clearTimeout(t));
    document.getElementById("scanProgress").style.display = "none";
    setDeviceStatus("error", "Error");
    showToast(`Scan error: ${e.message}`, "error");
  } finally {
    btnScan.disabled = false;
  }
}

function setProgressStep(step, allDone = false) {
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`step${i}`);
    if (!el) continue;
    el.classList.remove("active", "done");
    if (allDone || i < step) {
      el.classList.add("done");
    } else if (i === step) {
      el.classList.add("active");
    }
  }
}

// ── Render Scan Report ───────────────────────────────────────────
function renderScanReport(report) {
  const dev = report.device || {};
  const sum = report.severity_summary || {};

  document.getElementById("reportDeviceName").textContent =
    `${dev.manufacturer || ""} ${dev.model || ""}`.trim() || "Unknown Device";

  document.getElementById("reportDeviceDetails").textContent =
    [
      dev.android_version ? `Android ${dev.android_version}` : null,
      dev.sdk_version     ? `SDK ${dev.sdk_version}` : null,
      dev.security_patch  ? `Patch: ${dev.security_patch}` : null,
      dev.cpu_abi         ? dev.cpu_abi : null,
      dev.build_id        ? `Build ${dev.build_id}` : null,
    ].filter(Boolean).join("  •  ");

  document.getElementById("reportScanTime").textContent =
    `Scanned: ${new Date(report.scan_time).toLocaleString()}`;
  document.getElementById("reportPackages").textContent =
    `${report.packages_scanned.toLocaleString()} packages scanned`;

  document.getElementById("rCritical").textContent = sum.CRITICAL || 0;
  document.getElementById("rHigh").textContent     = sum.HIGH     || 0;
  document.getElementById("rMedium").textContent   = sum.MEDIUM   || 0;
  document.getElementById("rLow").textContent      = sum.LOW      || 0;
  document.getElementById("rTotal").textContent    = report.total_vulnerabilities || 0;

  // Build category pills
  const categories = [...new Set(allVulnerabilities.map(v => v.match_category).filter(Boolean))];
  const pillsEl = document.getElementById("categoryPills");
  pillsEl.innerHTML = categories.map(cat =>
    `<button class="cat-pill" onclick="filterByCategory('${cat}')">${catLabel(cat)}</button>`
  ).join("");

  renderReportTable(allVulnerabilities);

  document.getElementById("scanResults").style.display = "flex";
  loadScanHistory();
}

function catLabel(cat) {
  return { os: "🤖 Android OS", kernel: "🐧 Kernel", manufacturer: "🏭 Manufacturer", package: "📦 Apps" }[cat] || cat;
}

function renderReportTable(vulns) {
  const tbody = document.getElementById("reportTableBody");
  if (!vulns.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="loading-row" style="color:var(--low)">
      ✅ No vulnerabilities found for this filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = vulns.map(cve => {
    const scoreClass = cvssClass(cve.cvss_score);
    const severity   = cve.severity || "UNKNOWN";
    const badgeLabel = severity === "UNKNOWN" ? "PENDING" : severity;
    const summary    = truncate(cve.description, 80);
    const cat        = cve.match_category || "os";

    return `
      <tr onclick="openModal('${escHtml(cve.cve_id)}')">
        <td class="cve-id-cell">${escHtml(cve.cve_id)}</td>
        <td><span class="badge badge-${severity}">${badgeLabel}</span></td>
        <td class="cvss-score ${scoreClass}">${cve.cvss_score ?? '—'}</td>
        <td><span class="match-category match-${cat}">${catLabel(cat)}</span></td>
        <td class="summary-cell" title="${escHtml(cve.description)}">${escHtml(summary)}</td>
        <td onclick="event.stopPropagation()">
          <button class="btn-detail" onclick="openModal('${escHtml(cve.cve_id)}')">Details</button>
        </td>
      </tr>`;
  }).join("");
}

function filterReport() {
  const val = document.getElementById("reportSeverityFilter").value;
  let filtered = allVulnerabilities;

  // Category filters
  const catFilters = ["os", "kernel", "manufacturer", "package"];
  if (catFilters.includes(val)) {
    filtered = filtered.filter(v => v.match_category === val);
  } else if (val !== "ALL") {
    filtered = filtered.filter(v => (v.severity || "UNKNOWN") === val);
  }

  renderReportTable(filtered);
}

function filterByCategory(cat) {
  document.querySelectorAll(".cat-pill").forEach(p => {
    p.classList.toggle("active", p.textContent === catLabel(cat) || p.onclick?.toString().includes(`'${cat}'`));
  });
  const filtered = allVulnerabilities.filter(v => v.match_category === cat);
  renderReportTable(filtered);
}

// ── Scan History ─────────────────────────────────────────────────
async function loadScanHistory() {
  try {
    const res = await fetch(`${API}/api/android/history`);
    const data = await res.json();
    const scans = data.scans || [];

    const histEl = document.getElementById("scanHistory");
    const listEl = document.getElementById("scanHistoryList");

    if (!scans.length) {
      histEl.style.display = "none";
      return;
    }

    listEl.innerHTML = scans.map(s => `
      <div class="history-item">
        <div class="history-device">📱 ${s.manufacturer || ""} ${s.model || "Unknown"}
          <span class="history-android"> Android ${s.android_version || "?"}</span>
        </div>
        <div class="history-patch">Patch: ${s.security_patch || "unknown"}</div>
        <div class="history-vulns">
          ${s.critical_count ? `<span class="history-vuln-pill hv-critical">C: ${s.critical_count}</span>` : ""}
          ${s.high_count ? `<span class="history-vuln-pill hv-high">H: ${s.high_count}</span>` : ""}
          <span style="font-size:12px;color:var(--text-muted)">${s.total_vulns} total</span>
        </div>
        <div class="history-time">${new Date(s.scan_time).toLocaleString()}</div>
      </div>
    `).join("");

    histEl.style.display = "block";
  } catch (e) {
    // history is non-critical, fail silently
  }
}

// Listen for android scan complete SSE events
const _origConnectSSE = connectSSE;
// Extend SSE handler for android events (patch into the existing source)
const _origSSEConnect = connectSSE;
document.addEventListener("DOMContentLoaded", () => {
  // Extend existing SSE with android_scan_complete handler
  const origConnect = window.connectSSE;
  window.connectSSE = function() {
    origConnect && origConnect();
    if (window.sseSource) {
      window.sseSource.addEventListener("android_scan_complete", (e) => {
        const d = JSON.parse(e.data);
        showToast(
          `📱 Scan done: ${d.device} — ${d.total_vulns} CVEs (${d.critical} critical)`,
          d.critical > 0 ? "error" : "success",
          6000
        );
      });
    }
  };
});
