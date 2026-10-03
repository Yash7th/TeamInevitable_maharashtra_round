const state = { files: [], reports: [] };
const input = document.querySelector("#fileInput");
const dropzone = document.querySelector("#dropzone");
const fileList = document.querySelector("#fileList");
const fileCount = document.querySelector("#fileCount");
const queueHint = document.querySelector("#queueHint");
const verifyButton = document.querySelector("#verifyButton");
const reportSection = document.querySelector("#history");
const reportText = document.querySelector("#reportText");
const reportStatus = document.querySelector("#reportStatus");
const reportTime = document.querySelector("#reportTime");
const toast = document.querySelector("#toast");
const modelGrid = document.querySelector("#modelGrid");
const modelCount = document.querySelector("#modelCount");
const historyList = document.querySelector("#historyList");
const historyBadge = document.querySelector("#historyBadge");
const historyNav = document.querySelector("#historyNav");
const historyStorageKey = "modelledger-verification-history";

const allowed = ["image/", "application/pdf", "video/"];
const maxBytes = 250 * 1024 * 1024;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 3000);
}

function isSupported(file) {
  return allowed.some((type) => type.endsWith("/") ? file.type.startsWith(type) : file.type === type);
}

function formatSize(bytes) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function fileKind(file) {
  if (file.type.startsWith("image/")) return "IMG";
  if (file.type === "application/pdf") return "PDF";
  return "VID";
}

function renderQueue() {
  fileCount.textContent = `${state.files.length} file${state.files.length === 1 ? "" : "s"}`;
  queueHint.textContent = state.files.length ? "Ready to verify" : "Waiting for upload";
  verifyButton.disabled = !state.files.length;
  if (!state.files.length) {
    fileList.innerHTML = '<div class="empty-queue"><span>＋</span><p>Your selected files will appear here</p></div>';
    return;
  }
  fileList.innerHTML = state.files.map((file, index) => `
    <div class="file-row">
      <div class="file-preview">${fileKind(file)}</div>
      <div class="file-details"><div class="file-name">${escapeHtml(file.name)}</div><div class="file-size">${formatSize(file.size)} · ${escapeHtml(file.type || "unknown type")}</div></div>
      <button class="remove-file" type="button" data-index="${index}" aria-label="Remove ${escapeHtml(file.name)}">×</button>
    </div>`).join("");
  fileList.querySelectorAll(".remove-file").forEach((button) => {
    button.addEventListener("click", () => { state.files.splice(Number(button.dataset.index), 1); renderQueue(); });
  });
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]);
}

function addFiles(fileCollection) {
  const incoming = [...fileCollection];
  const valid = incoming.filter((file) => isSupported(file) && file.size <= maxBytes);
  const rejected = incoming.length - valid.length;
  const existing = new Set(state.files.map((file) => `${file.name}:${file.size}:${file.lastModified}`));
  valid.forEach((file) => {
    const key = `${file.name}:${file.size}:${file.lastModified}`;
    if (!existing.has(key)) state.files.push(file);
  });
  if (rejected) showToast(`${rejected} file${rejected === 1 ? "" : "s"} rejected: unsupported type or over 250 MB.`);
  renderQueue();
}

async function sha256(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function selectedModels() {
  return [...modelGrid.querySelectorAll("input:checked")].map((input) => input.value);
}

function detectorReport(models) {
  if (!models.length) return "No AI-origin detectors selected.";
  return models.map((key) => {
    if (key === "forensic") return "- Local forensic checks: SIGNAL UNAVAILABLE (a backend parser is required for this file type)";
    if (key === "content") return "- Content detector adapter: NOT CONFIGURED (connect your detector API endpoint)";
    return "- Provenance ledger: NO MATCHING SIGNED EVENT (a changed hash cannot prove AI generation)";
  }).join("\n");
}

function loadHistory() {
  try {
    const saved = JSON.parse(localStorage.getItem(historyStorageKey) || "[]");
    return Array.isArray(saved) ? saved : [];
  } catch (error) {
    showToast("Saved verification history could not be loaded.");
    return [];
  }
}

function saveHistory(item) {
  const history = loadHistory();
  history.unshift(item);
  localStorage.setItem(historyStorageKey, JSON.stringify(history.slice(0, 50)));
  renderHistory();
}

function renderHistory() {
  const history = loadHistory();
  historyBadge.hidden = !history.length;
  historyBadge.textContent = history.length;
  if (!history.length) {
    historyList.innerHTML = '<div class="history-empty">Completed reports will be saved here automatically in this browser.</div>';
    return;
  }
  historyList.innerHTML = history.map((item, index) => `
    <div class="history-item">
      <div class="history-item-icon">✓</div>
      <div class="history-item-main"><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.createdAt)} · ${item.fileCount} artifact${item.fileCount === 1 ? "" : "s"}</small></div>
      <button type="button" data-history-index="${index}">View report</button>
    </div>`).join("");
  historyList.querySelectorAll("[data-history-index]").forEach((button) => {
    button.addEventListener("click", () => {
      const item = loadHistory()[Number(button.dataset.historyIndex)];
      if (!item) return;
      reportText.textContent = item.report;
      reportStatus.textContent = item.status;
      reportStatus.className = `report-status ${item.statusClass}`;
      reportTime.textContent = `${item.fileCount} artifact${item.fileCount === 1 ? "" : "s"} · saved ${item.createdAt}`;
      reportSection.hidden = false;
      reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

function reportFor(file, hash) {
  const now = new Date();
  const typeLabel = file.type.startsWith("image/") ? "image" : file.type === "application/pdf" ? "PDF document" : "video";
  return `MODELLEDGER PROVENANCE REPORT
Generated: ${now.toLocaleString()}

ARTIFACT
Name: ${file.name}
Type: ${typeLabel}
Size: ${formatSize(file.size)}
SHA-256: ${hash}

ORIGIN
AI-generated: Not determinable from the file alone
Specific AI system: No signed attribution found
Evidence: No connected ledger event was available for this browser-only check

TRANSFORMATION HISTORY
Recorded modifications: No verifiable transformation events found
Modified how many times: Unknown
Modified by: Unknown

MULTI-MODEL AI ORIGIN CHECK
${detectorReport(selectedModels())}
Consensus: INCONCLUSIVE — no configured detector returned a classification

VERIFICATION NOTES
The file fingerprint was calculated locally. A definitive origin, model identity,
or modification timeline requires matching signed ModelLedger events. Uploading
the file does not by itself prove that it was or was not AI-generated.
`;
}

async function verifyFiles() {
  verifyButton.disabled = true;
  verifyButton.innerHTML = "Hashing files <span>…</span>";
  const started = performance.now();
  const reports = [];
  for (const file of state.files) reports.push(reportFor(file, await sha256(file)));
  state.reports = reports;
  const elapsed = Math.max(1, Math.round(performance.now() - started));
  reportText.textContent = reports.join("\n\n" + "—".repeat(55) + "\n\n");
  reportStatus.textContent = "Evidence incomplete";
  reportStatus.className = "report-status untrusted";
  reportTime.textContent = `${state.files.length} artifact${state.files.length === 1 ? "" : "s"} · ${elapsed} ms`;
  saveHistory({
    label: state.files.length === 1 ? state.files[0].name : `${state.files.length} uploaded artifacts`,
    report: reportText.textContent,
    createdAt: new Date().toLocaleString(),
    fileCount: state.files.length,
    status: "Evidence incomplete",
    statusClass: "untrusted",
  });
  reportSection.hidden = false;
  reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
  verifyButton.disabled = false;
  verifyButton.innerHTML = "Verify selected files <span>→</span>";
}

document.querySelector("#browseButton").addEventListener("click", () => input.click());
dropzone.addEventListener("click", (event) => { if (event.target === dropzone || event.target.closest(".upload-orb")) input.click(); });
dropzone.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") input.click(); });
input.addEventListener("change", (event) => { addFiles(event.target.files); input.value = ""; });
["dragenter", "dragover"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.add("dragover"); }));
["dragleave", "drop"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.remove("dragover"); }));
dropzone.addEventListener("drop", (event) => addFiles(event.dataTransfer.files));
verifyButton.addEventListener("click", verifyFiles);
document.querySelector("#copyReport").addEventListener("click", async () => {
  await navigator.clipboard.writeText(reportText.textContent);
  showToast("Report copied to clipboard.");
});
modelGrid.addEventListener("change", (event) => {
  const card = event.target.closest(".model-card");
  if (card) card.classList.toggle("selected", event.target.checked);
  modelCount.textContent = `${selectedModels().length} selected`;
});
historyNav.addEventListener("click", () => {
  reportSection.hidden = false;
  renderHistory();
});
document.querySelector("#clearHistory").addEventListener("click", () => {
  localStorage.removeItem(historyStorageKey);
  renderHistory();
  showToast("Verification history cleared.");
});
renderHistory();
renderQueue();
