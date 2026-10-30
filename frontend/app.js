// AI-SOC dashboard. All scanned URLs are untrusted text: they are only ever
// written with textContent, never innerHTML, so a malicious URL cannot inject script.
const API = "/api/v1";
const $ = (id) => document.getElementById(id);
const SOURCE_LABELS = { blocklist: "Threat-intel blocklist", whitelist: "Trusted-domain list", "ml+rules": "ML model + rules", rules: "Rules only" };

async function api(path, options) {
  const res = await fetch(API + path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + res.status + ")");
  return data;
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function showResult(r) {
  const cls = r.verdict.toLowerCase();
  $("result-card").hidden = false;
  $("r-url").textContent = r.url;
  const verdict = $("r-verdict");
  verdict.textContent = r.verdict;
  verdict.className = "badge " + cls;
  $("r-score").textContent = r.score + "/100";
  $("r-score").className = cls;
  $("r-bar").style.width = r.score + "%";
  $("r-bar").className = cls;
  $("r-severity").textContent = r.severity;
  $("r-severity").className = cls;
  $("r-confidence").textContent = r.confidence + "%";
  $("r-source").textContent = SOURCE_LABELS[r.source] || r.source;
  const list = $("r-reasons");
  list.replaceChildren(...r.reasons.map((text) => el("li", text)));
  $("r-note").textContent = r.scan_count > 1 ? "Scanned " + r.scan_count + " times" + (r.cached ? " (saved result reused)" : "") + "." : "";
}

async function loadStats() {
  const s = await api("/stats");
  $("s-total").textContent = s.total_scans;
  $("s-safe").textContent = s.verdicts.Safe;
  $("s-susp").textContent = s.verdicts.Suspicious;
  $("s-mal").textContent = s.verdicts.Malicious;
  $("s-note").textContent = s.unique_urls + " unique URLs (Safe + Suspicious + Malicious). Total Scans includes repeats.";
}

async function loadHistory() {
  const verdict = $("filter").value;
  const data = await api("/history?limit=100" + (verdict ? "&verdict=" + encodeURIComponent(verdict) : ""));
  const body = $("history-body");
  body.replaceChildren(...data.items.map((r) => {
    const cls = r.verdict.toLowerCase();
    const tr = el("tr");
    const urlCell = el("td", r.url, "url-cell");
    urlCell.title = r.url;
    const badge = el("span", r.verdict, "badge " + cls);
    const verdictCell = el("td"); verdictCell.append(badge);
    const sev = el("td"); sev.append(el("strong", r.severity, "severity " + cls));
    const score = el("td"); score.append(el("strong", r.score + "/100", cls));
    tr.append(el("td", "#" + r.id), urlCell, verdictCell, sev, score, el("td", String(r.scan_count)),
      el("td", new Date(r.last_scanned_at).toLocaleString()));
    return tr;
  }));
  $("empty").hidden = data.items.length > 0;
}

async function refresh() { await Promise.all([loadStats(), loadHistory()]); }

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("url-input");
  const btn = $("scan-btn");
  $("error").hidden = true;
  btn.disabled = true; btn.textContent = "Scanning…";
  try {
    showResult(await api("/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: input.value }) }));
    await refresh();
  } catch (err) {
    $("error").textContent = err.message;
    $("error").hidden = false;
  } finally {
    btn.disabled = false; btn.textContent = "Scan URL";
  }
});
$("filter").addEventListener("change", () => loadHistory().catch(() => {}));

(async () => {
  try {
    const h = await api("/health");
    $("status").className = "status online";
    $("status-text").textContent = "System Online (" + h.detector_mode + ")";
    await refresh();
  } catch {
    $("status").className = "status offline";
    $("status-text").textContent = "Backend offline";
  }
})();
