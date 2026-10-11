/* IR Platform — lógica de la interfaz.
 * Seguridad (OWASP XSS Prevention): los datos de los logs (user agents, IPs, textos del LLM) son
 * controlados por terceros. NUNCA se insertan con innerHTML: todo el DOM se construye con
 * textContent/createElement mediante el helper `el()`. Los POST llevan la cabecera X-CSRF-Token.
 */
"use strict";

const CSRF = document.querySelector('meta[name="csrf-token"]').content;
const COLORS = { c1: "#3987e5", c2: "#d95926", neutral: "#c3c2b7", grid: "rgba(255,255,255,0.08)", text: "#c3c2b7" };
const LEVEL_ICON = { critico: "⛔", alto: "▲", medio: "●", bajo: "○" };
const state = { run: null, summary: null, charts: {}, agentsJob: null, selectedDataset: null, llm: null, ti: null };

/* ---------------------------------------------------------------- utilidades */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);
const fmt = (n) => (typeof n === "number" ? n.toLocaleString("es-CO") : n ?? "—");
const pct = (x) => (typeof x === "number" ? `${Math.round(x * 100)} %` : "—");
const bytes = (b) => (b > 1e9 ? `${(b / 1e9).toFixed(2)} GB` : b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${fmt(b)} B`);
const short = (s, n = 16) => (s && s.length > n ? `${s.slice(0, n)}…` : s);
const when = (iso) => (iso ? iso.replace("T", " ").slice(0, 16) : "—");

async function api(path, options = {}) {
  const opts = { ...options, headers: { ...(options.headers || {}) } };
  if (opts.method && opts.method !== "GET") opts.headers["X-CSRF-Token"] = CSRF;
  if (opts.json !== undefined) {
    opts.body = JSON.stringify(opts.json);
    opts.headers["Content-Type"] = "application/json";
    delete opts.json;
  }
  const res = await fetch(path, opts);
  if (res.status === 401) { window.location = "/login"; throw new Error("No autenticado"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    const detail = Array.isArray(data?.detail) ? data.detail.map((d) => `${d.loc?.slice(-1)[0] ?? ""}: ${d.msg}`).join("; ") : data?.detail;
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return data;
}

function levelTag(level) {
  return el("span", { class: `level ${level}` }, LEVEL_ICON[level] || "", " ", level);
}
function campaignBadge(cid) {
  if (!cid) return "—";
  return el("span", { class: `badge ${cid.toLowerCase()}` }, cid);
}
function table(node, headers, rows) {
  node.replaceChildren(
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", { class: h.num ? "num" : null }, typeof h === "string" ? h : h.label ?? "")))),
    el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c, i) => el("td", { class: headers[i]?.num ? "num" : null }, c))))),
  );
}
function downloadLink(id, artifact) {
  const a = $(id);
  if (!state.run) { a.removeAttribute("href"); return; }
  a.href = `/api/runs/${state.run}/download/${artifact}`;
}

/* ---------------------------------------------------------------- pestañas */
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${t.dataset.tab}`));
    // Los gráficos creados con la pestaña oculta miden 0 px: se redimensionan al mostrarla.
    if (t.dataset.tab === "investigation") requestAnimationFrame(() => Object.values(state.charts).forEach((c) => c.resize()));
  }),
);

/* ---------------------------------------------------------------- 1 · Dataset */
async function loadDatasets() {
  const list = await api("/api/datasets");
  $("dataset-list").replaceChildren(
    ...(list.length ? list.map((d) =>
      el("label", {},
        el("input", { type: "radio", name: "dataset", value: d.name, onchange: () => { state.selectedDataset = d.name; $("analyze-btn").disabled = false; } }),
        el("span", {}, d.name), el("span", { class: "muted" }, bytes(d.size_bytes)),
        d.custody ? el("span", { class: "badge ok", title: "Tiene acta de cadena de custodia" }, "custodia") : null,
        d.read_only ? el("span", { class: "badge", title: "Protegido contra escritura" }, "solo lectura") : null)) :
      [el("p", { class: "muted" }, "No hay CSV en data/.")]),
  );
}

const CUSTODY_FIELDS = ["collected_by", "collected_at", "source_system", "source_timezone", "case_id", "evidence_id",
  "collection_method", "authorization", "received_by", "source_sha256", "description", "notes"];
const CUSTODY_REQUIRED = { collected_by: "Recolectado por", collected_at: "Fecha de recolección", source_system: "Sistema de origen", source_timezone: "Zona horaria" };
/* Acta de cadena de custodia: campos que solo puede aportar el analista (validación también en el servidor). */
function custodyIntake() {
  const data = {};
  CUSTODY_FIELDS.forEach((k) => { const v = $(`cu-${k}`).value.trim(); if (v) data[k] = v; });
  const missing = Object.keys(CUSTODY_REQUIRED).filter((k) => !data[k]);
  CUSTODY_FIELDS.forEach((k) => $(`cu-${k}`).classList.toggle("invalid", missing.includes(k)));
  if (missing.length) return { error: `Complete los campos de cadena de custodia: ${missing.map((k) => CUSTODY_REQUIRED[k]).join(", ")}` };
  if (data.source_sha256 && !/^[0-9a-fA-F]{64}$/.test(data.source_sha256)) {
    $("cu-source_sha256").classList.add("invalid");
    return { error: "El SHA-256 de origen debe tener 64 caracteres hexadecimales" };
  }
  if (new Date(data.collected_at) > new Date(Date.now() + 86400000)) {
    $("cu-collected_at").classList.add("invalid");
    return { error: "La fecha de recolección no puede estar en el futuro" };
  }
  return { data };
}

$("custody-form").addEventListener("input", (e) => e.target.classList.remove("invalid"));
$("upload-btn").addEventListener("click", () => {
  const file = $("upload-input").files[0];
  if (!file) { $("upload-msg").textContent = "Seleccione un archivo .csv"; return; }
  const intake = custodyIntake();
  if (intake.error) { $("upload-msg").textContent = intake.error; return; }
  const xhr = new XMLHttpRequest();
  const bar = $("upload-progress");
  bar.hidden = false; bar.value = 0;
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) bar.value = (e.loaded / e.total) * 100; };
  xhr.onload = async () => {
    bar.hidden = true;
    let data = {};
    try { data = JSON.parse(xhr.responseText); } catch { /* respuesta no JSON */ }
    if (xhr.status === 200) {
      const match = data.source_hash_match === true ? " · coincide con el hash de origen" : "";
      $("upload-msg").textContent = `Cargado como ${data.name} · ${data.evidence_id} · SHA-256 ${data.sha256}${match} · ${data.read_only ? "protegido contra escritura" : "no se pudo marcar como solo lectura (el hash sigue siendo la garantía)"}`;
      $("custody-form").reset();
      $("upload-input").value = "";
    } else {
      $("upload-msg").textContent = `Error: ${data.detail || xhr.status}`;
    }
    await loadDatasets();
  };
  xhr.onerror = () => { bar.hidden = true; $("upload-msg").textContent = "Error de red durante la carga"; };
  xhr.open("POST", "/api/datasets/upload");
  xhr.setRequestHeader("X-CSRF-Token", CSRF);
  xhr.setRequestHeader("X-Filename", encodeURIComponent(file.name));
  xhr.setRequestHeader("X-Custody-Metadata", encodeURIComponent(JSON.stringify(intake.data)));
  xhr.send(file);
});

const ANALYSIS_STAGES = [
  ["hash", "SHA-256"], ["incident", "Perfil del incidente"], ["profile", "Esquema y perfil"], ["staging", "Parquet"], ["metrics", "Métricas"],
  ["detection", "Detección + scoring"], ["evidence", "Evidencia"], ["verify", "Re-hash"], ["completed", "Listo"],
];
function renderStages(node, stages, current, failed = false) {
  const idx = stages.findIndex(([k]) => k === current);
  node.replaceChildren(...stages.map(([k, label], i) =>
    el("li", { class: failed && i === idx ? "failed" : i < idx || current === "completed" ? "done" : i === idx ? "active" : null }, label)));
}

/* Perfil del incidente: se DETECTA del dataset en cada análisis. El formulario manual es opcional y se precarga
   con lo detectado en el run seleccionado (o con los valores de .env si aún no hay runs). */
const PROFILE_FIELDS = ["target_endpoint", "object_param", "scope_param", "token_param", "object_label", "object_label_plural", "scope_label"];
const DEFAULT_PROFILE = { endpoint: "/invoices/search", object_param: "invoice_id", scope_param: "site_id", token_param: "authtoken",
  object_label: "factura", object_label_plural: "facturas", scope_label: "sitio" };
function fillProfileForm(src) {
  const p = src || state.config?.profile || {};
  PROFILE_FIELDS.forEach((k) => ($(`pf-${k}`).value = (k === "target_endpoint" ? p.endpoint ?? p.target_endpoint : p[k]) ?? ""));
}
function setManual(on) {
  $("pf-manual").checked = on;
  document.querySelectorAll("#profile-form input").forEach((i) => (i.disabled = !on));
}
function profilePayload() {
  const out = { detection_date: $("pf-detection_date").value, profile_mode: $("pf-manual").checked ? "manual" : "auto" };
  if ($("pf-manual").checked) PROFILE_FIELDS.forEach((k) => (out[k] = $(`pf-${k}`).value.trim()));
  return out;
}
$("pf-manual").addEventListener("change", (e) => setManual(e.target.checked));
const CONF_CLASS = { alta: "ok", media: "warn", baja: "bad" };
/* Perfil detectado en el run seleccionado (manifiesto): qué se analizó y por qué. */
function renderDetectedProfile() {
  const params = state.summary?.manifest?.parameters || {};
  const prof = params.incident_profile, inf = params.incident_profile_inference;
  const box = $("profile-detected");
  if (!prof) { box.hidden = true; return; }
  const auto = inf?.mode === "automático";
  const overrides = Object.keys(inf?.overrides || {});
  const req = `GET ${prof.endpoint}?${[prof.object_param, prof.scope_param, prof.token_param].filter(Boolean).map((k) => `${k}=…`).join("&")}`;
  box.replaceChildren(
    el("div", { class: "row" },
      el("strong", {}, auto ? "Perfil detectado en el run seleccionado" : "Perfil usado en el run seleccionado"),
      auto && inf.confidence ? el("span", { class: `badge ${CONF_CLASS[inf.confidence] || ""}` }, `confianza ${inf.confidence}`) : null,
      overrides.length ? el("span", { class: "badge warn" }, `ajustado: ${overrides.join(", ")}`) : null),
    el("div", { class: "mono" }, req),
    el("div", { class: "muted small" }, `Objetos: ${prof.object_label_plural}${prof.scope_param ? ` · ámbito: ${prof.scope_label}` : " · sin ámbito"}`),
    inf?.evidence?.length ? el("ul", { class: "reasons" }, inf.evidence.map((x) => el("li", {}, x))) : null,
    el("a", { class: "btn ghost small", href: `/api/runs/${state.run}/download/profile.json` }, "profile.json (perfil del dataset)"));
  box.hidden = false;
  if (!$("pf-manual").checked) fillProfileForm(prof);
  $("pf-endpoints").replaceChildren(...(inf?.candidates || []).map((c) => el("option", { value: c.endpoint }, `${c.object_param} · ${fmt(c.requests)} pet.`)));
}
/* Perfil del run mostrado (metadata de la evidencia); runs antiguos → valores del reto. */
const runProfile = () => ({ ...DEFAULT_PROFILE, ...(state.summary?.evidence?.metadata?.profile || {}) });
const cap = (t) => (t ? t[0].toUpperCase() + t.slice(1) : t);

$("analyze-btn").addEventListener("click", async () => {
  if (!state.selectedDataset) return;
  $("analyze-btn").disabled = true;
  renderStages($("analysis-steps"), ANALYSIS_STAGES, "hash");
  try {
    const { job_id } = await api("/api/analyses", { method: "POST", json: { dataset: state.selectedDataset, ...profilePayload() } });
    followJob(job_id, (ev) => {
      if (ANALYSIS_STAGES.some(([k]) => k === ev.kind)) renderStages($("analysis-steps"), ANALYSIS_STAGES, ev.kind);
      if (ev.kind === "failed") renderStages($("analysis-steps"), ANALYSIS_STAGES, "verify", true);
    }, async (job) => {
      $("analyze-btn").disabled = false;
      if (job.status === "completed" && job.result) { await loadRuns(job.result.run_id); }
    });
  } catch (e) { alertMsg(e); $("analyze-btn").disabled = false; }
});

function followJob(jobId, onEvent, onEnd) {
  const source = new EventSource(`/api/jobs/${jobId}/events`);
  source.onmessage = (m) => onEvent(JSON.parse(m.data));
  source.addEventListener("end", async () => { source.close(); onEnd(await api(`/api/jobs/${jobId}`)); });
  source.onerror = async () => {
    source.close();
    const job = await api(`/api/jobs/${jobId}`);
    if (["completed", "failed"].includes(job.status)) onEnd(job);
    else setTimeout(() => followJob(jobId, onEvent, onEnd), 2000);
  };
}
function alertMsg(e) { console.error(e); window.alert(e.message || String(e)); }

async function loadRuns(select) {
  const runs = await api("/api/runs");
  const sel = $("run-select");
  sel.replaceChildren(...runs.map((r) => el("option", { value: r.run_id }, `${r.run_id}${r.has_agents ? " ✦" : ""}`)));
  table($("runs-table"), ["Run", "Fecha (UTC)", "Archivo", "SHA-256", "Evidencia", "Agentes", ""],
    runs.map((r) => [el("span", { class: "mono" }, r.run_id), when(r.created), r.source, el("span", { class: "mono" }, short(r.sha256, 16)),
      r.has_evidence ? "sí" : "no", r.has_agents ? "sí" : "no",
      el("button", { class: "btn ghost small", type: "button", onclick: () => selectRun(r.run_id) }, "Ver")]));
  const target = select || (runs.find((r) => r.has_agents) || runs[0])?.run_id;
  if (target) await selectRun(target);
}
$("run-select").addEventListener("change", (e) => selectRun(e.target.value));

async function selectRun(runId) {
  state.run = runId;
  $("run-select").value = runId;
  state.summary = await api(`/api/runs/${runId}`);
  renderDetectedProfile();
  renderInvestigation();
  renderEvidence();
  renderAgents();
  loadEvaluations().catch(console.error);
  if ($("tab-chat").classList.contains("active")) loadChat().catch(console.error);
}

/* ---------------------------------------------------------------- 2 · Investigación */
function chart(id, config) {
  if (state.charts[id]) state.charts[id].destroy();
  if (!window.Chart) return;
  Chart.defaults.color = COLORS.text;
  Chart.defaults.font.family = "system-ui, -apple-system, Segoe UI, sans-serif";
  Chart.defaults.animation = false; // sin animaciones: lectura inmediata y capturas estables
  state.charts[id] = new Chart($(id), config);
}
const axes = (stacked = false) => ({
  x: { stacked, grid: { display: false }, ticks: { maxTicksLimit: 8 } },
  y: { stacked, beginAtZero: true, grid: { color: COLORS.grid } },
});

function renderInvestigation() {
  const s = state.summary;
  downloadLink("dl-metrics", "metrics.json");
  downloadLink("dl-detection", "detection.json");
  const p = s.profile || {}, m = s.metrics || {}, ev = s.evidence || {}, det = s.detection || {};
  const crit = det.source_ip?.levels?.critico ?? 0;
  const ans = ev.incident_answers || {};
  const pr = runProfile();
  const det_date = ev.response_metrics?.detection_date;
  $("total-endpoint").textContent = pr.endpoint;
  const kpis = [
    ["Registros", fmt(p.total_rows), `${when(p.first_timestamp)} → ${when(p.last_timestamp)}`],
    ["IPs únicas", fmt(p.unique_source_ips), `${fmt(det.authtoken?.total)} tokens`],
    ["IPs críticas", fmt(crit), `${fmt(det.source_ip?.levels?.alto ?? 0)} alto · ${fmt(det.source_ip?.levels?.medio ?? 0)} medio`],
    [`${cap(pr.object_label_plural)} · IDs únicos 2xx`, fmt(ans["3_facturas_accedidas_indebidamente"]?.unique_invoices_2xx), "campañas confirmadas"],
    ["TTD", ans.ttd_dias != null ? `${ev.response_metrics?.ttd_is_estimate ? "≈ " : ""}${ans.ttd_dias} días` : "—",
      det_date ? `detección ${when(det_date)}` : ev.response_metrics?.ttd_reference ? `estimado al fin del log (${when(ev.response_metrics.ttd_reference)})` : "sin fecha de detección"],
  ];
  $("kpis").replaceChildren(...kpis.map(([l, v, sub]) => el("div", { class: "kpi" }, el("div", { class: "label" }, l), el("div", { class: "value" }, v), el("div", { class: "sub" }, sub))));

  // Ataque por día y campaña (una sola escala; el tráfico total va en su propio gráfico).
  const camps = ev.campaigns || [];
  const days = (m.temporal?.per_day || []).map((d) => d.day);
  const color = (c) => (c.campaign_id === "C1" ? COLORS.c1 : COLORS.c2);
  chart("chart-attack", {
    type: "bar",
    data: { labels: days, datasets: camps.map((c) => {
      const byDay = Object.fromEntries(c.daily.map((d) => [d.day, d.requests]));
      return { label: `${c.campaign_id} (${c.status.replace("_", " ")})`, data: days.map((d) => byDay[d] || 0),
        backgroundColor: color(c), borderRadius: 2, borderSkipped: false, barPercentage: 0.9, categoryPercentage: 1 };
    }) },
    options: { maintainAspectRatio: false, interaction: { mode: "index", intersect: false }, scales: axes(true),
      plugins: { legend: { display: camps.length > 1, labels: { boxWidth: 12 } } } },
  });
  chart("chart-total", {
    type: "line",
    data: { labels: days, datasets: [{ label: "Peticiones", data: (m.temporal?.per_day || []).map((d) => d.requests),
      borderColor: COLORS.neutral, borderWidth: 2, pointRadius: 0, tension: 0 }] },
    options: { maintainAspectRatio: false, interaction: { mode: "index", intersect: false }, scales: axes(), plugins: { legend: { display: false } } },
  });
  const sc = Object.entries(p.status_counts || {}).sort((a, b) => Number(a[0]) - Number(b[0]));
  chart("chart-status", {
    type: "bar",
    data: { labels: sc.map(([k]) => k), datasets: [{ label: "Peticiones", data: sc.map(([, v]) => v), backgroundColor: COLORS.neutral, borderRadius: 4 }] },
    options: { maintainAspectRatio: false, scales: axes(), plugins: { legend: { display: false } } },
  });
  const er = m.error_rates || {};
  $("error-rates").textContent = `401: ${fmt(er.count_401)} · 403: ${fmt(er.count_403)} · 200: ${fmt(er.count_200)} · (401+403)/200 = ${er.ratio_401_403_vs_200 ?? "—"} · 2xx ${pct(er.ratio_2xx)} · 4xx ${pct(er.ratio_4xx)}`;

  const tok = det.authtoken?.actors || [];
  table($("tokens-table"),
    [{ label: "Token" }, { label: "Riesgo" }, { label: "Score", num: true }, { label: "Peticiones", num: true }, { label: cap(pr.object_label_plural), num: true }, { label: "Automat.", num: true }],
    tok.slice(0, 12).map((t) => [el("span", { class: "mono" }, t.token_hint), levelTag(t.risk_level), t.risk_score, fmt(t.requests), fmt(t.unique_invoices), pct(t.automation_ratio)]));
  const ips = (det.source_ip?.actors || []).slice(0, 25);
  table($("ips-table"),
    [{ label: "IP" }, { label: "Riesgo" }, { label: "Score", num: true }, { label: "Peticiones", num: true }, { label: cap(pr.object_label_plural), num: true }, { label: "2xx", num: true }, { label: "Automat.", num: true }, { label: "Razones" }],
    ips.map((r) => [el("span", { class: "mono" }, r.actor), levelTag(r.risk_level), r.risk_score, fmt(r.requests), fmt(r.unique_invoices), pct(r.success_ratio), pct(r.automation_ratio),
      el("ul", { class: "reasons" }, (r.reasons || []).map((x) => el("li", {}, x)))]));
}

/* ---------------------------------------------------------------- 3 · Evidencia */
/* Pregunta 1: dos momentos distintos. Reconocimiento = primera actividad (intentos); explotación = primer 2xx
   sobre un objeto ajeno (inicio de la exposición de datos). */
function startCard(ini, ev) {
  const censored = ini.inicio_censurado ?? /censurado/.test(ini.nota || "");
  const row = (label, value) => el("div", { class: "big-row" }, el("span", { class: "big-label" }, label), value);
  return el("div", {},
    row("Reconocimiento desde", `${censored ? "≤ " : ""}${when(ini.primera_actividad_maliciosa)}`),
    row("Explotación desde", when(ini.primer_acceso_exitoso_2xx)));
}
function startDetail(ini, ev) {
  const camp = (ev.campaigns || []).find((c) => c.status === "confirmada");
  const before = (camp?.phases || []).filter((p) => ini.primer_acceso_exitoso_2xx && p.end < ini.primer_acceso_exitoso_2xx.slice(0, 10));
  const recon = before.length ? `Antes de la explotación: ~${before[0].median_per_day} peticiones/día con éxito ${pct(before[0].success_ratio)} (intentos rechazados). ` : "";
  const ip = ini.ip_primer_acceso || camp?.exploitation_start?.source_ip;
  const first = ini.primer_acceso_exitoso_2xx ? `Primer acceso exitoso (2xx) a ${runProfile().object_label} de otro usuario${ip ? ` desde ${ip}` : ""}: inicio de la exposición de datos. ` : "";
  const censored = ini.inicio_censurado ?? /censurado/.test(ini.nota || "");
  return recon + first + (censored ? "La primera actividad coincide con el primer registro del log: pudo comenzar antes (dato censurado)." : ini.nota || "");
}

const CUSTODY_LABELS = [["evidence_id", "ID de evidencia"], ["case_id", "Caso / ticket"], ["collected_by", "Recolectado por"],
  ["collected_at", "Fecha de recolección"], ["source_system", "Sistema de origen"], ["source_timezone", "Zona horaria del log"],
  ["collection_method", "Método de extracción"], ["authorization", "Autorización"], ["received_by", "Recibido por"],
  ["description", "Descripción"], ["notes", "Observaciones"]];
/* Acta de cadena de custodia del archivo analizado (solo si se cargó por la web con el acta). */
function renderCustodyIntake() {
  const rec = state.summary?.custody_intake;
  const box = $("custody-intake");
  $("dl-custody").hidden = !rec;
  if (!rec) { box.hidden = true; box.replaceChildren(); return; }
  downloadLink("dl-custody", "custody_intake.json");
  const i = rec.intake || {}, a = rec.automatic || {};
  const ro = state.summary?.manifest?.parameters?.source_read_only;
  const rows = CUSTODY_LABELS.filter(([k]) => i[k]).map(([k, label]) => [label, k === "collected_at" ? when(i[k]) : i[k]]);
  rows.push(["Archivo original", a.original_filename], ["Recibido (UTC)", when(a.received_at_utc)],
    ["SHA-256 al recibir", el("span", { class: "mono" }, a.sha256)],
    ["Hash de origen", a.source_hash_match === true ? "coincide" : a.source_hash_match === false ? "NO coincide" : "no informado"]);
  box.replaceChildren(
    el("div", { class: "row" }, el("h3", {}, "Cadena de custodia · acta de recepción"),
      el("span", { class: "badge ok" }, "hash verificado al analizar"),
      ro ? el("span", { class: "badge" }, "original en solo lectura") : el("span", { class: "badge warn" }, "original sin protección de escritura")),
    el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])));
  box.hidden = false;
}

function renderEvidence() {
  const ev = state.summary.evidence;
  ["dl-evidence:evidence.json", "dl-iocs:iocs.csv", "dl-manifest:manifest.json"].forEach((x) => downloadLink(...x.split(":")));
  renderCustodyIntake();
  const man = state.summary.manifest || {};
  $("integrity").textContent = man.source ? `Original: ${man.source.name} · ${bytes(man.source.size_bytes)} · SHA-256 ${man.source.sha256}` : "";
  $("verify-results").replaceChildren();
  if (!ev) { $("answers").replaceChildren(el("p", { class: "muted" }, "Este run no tiene evidencia.")); return; }
  const a = ev.incident_answers || {};
  const pr = runProfile();
  const pairs = a["3_facturas_accedidas_indebidamente"]?.invoice_site_pairs_2xx;
  const cards = [
    ["1. ¿Cuándo comenzó?", startCard(a["1_inicio_explotacion"] || {}, ev), startDetail(a["1_inicio_explotacion"] || {}, ev)],
    ["2. ¿Evidencia clara de IDOR?", a["2_evidencia_idor"]?.respuesta, a["2_evidencia_idor"]?.fundamento],
    [`3. Alcance: ${pr.object_label_plural} (IDs únicos 2xx)`, fmt(a["3_facturas_accedidas_indebidamente"]?.unique_invoices_2xx), `${pr.scope_param && pairs != null ? `${fmt(pairs)} pares ${pr.object_label}–${pr.scope_label}. ` : ""}${a["3_facturas_accedidas_indebidamente"]?.nota || ""}`],
    ["4. ¿Patrón secuencial?", (a["4_patron_secuencial"]?.respuesta || "").split(",")[0],
      `${(a["4_patron_secuencial"]?.respuesta || "").split(",").slice(1).join(",").trim()}. ${a["4_patron_secuencial"]?.fundamento || ""}`],
    ["5. ¿Automatizado?", a["5_automatizado"]?.respuesta, a["5_automatizado"]?.fundamento],
    ["6. ¿Una o varias campañas?", `${a["6_campanas"]?.confirmadas ?? 0} confirmada · ${a["6_campanas"]?.por_validar ?? 0} por validar`, ""],
    ["7. ¿Usuarios afectados?", `≤ ${fmt(a["7_usuarios_potencialmente_afectados"]?.limite_superior)}`,
      `${pr.scope_param ? `Por ${pr.scope_label}: ${Object.entries(a["7_usuarios_potencialmente_afectados"]?.por_site_id || {}).map(([k, v]) => `${k}: ${fmt(v)}`).join(" · ")}. ` : ""}${a["7_usuarios_potencialmente_afectados"]?.nota || ""}`],
  ];
  $("answers").replaceChildren(...cards.map(([q, big, text]) => el("div", { class: "answer" }, el("div", { class: "q" }, q), el("div", { class: "big" }, big ?? "—"), el("div", { class: "a" }, text))));

  $("campaigns").replaceChildren(...(ev.campaigns || []).map((c) => el("div", { class: "card" },
    el("h3", {}, campaignBadge(c.campaign_id), " ", c.status === "confirmada" ? "Confirmada" : "Por validar"),
    el("p", { class: "muted" }, `${when(c.first_seen)} → ${when(c.last_seen)} · ${fmt(c.requests)} peticiones`),
    el("p", {}, "IPs: ", el("span", { class: "mono" }, c.ips.join(", "))),
    el("p", {}, "Tokens: ", el("span", { class: "mono" }, c.tokens.map((t) => t.hint).join(", "))),
    el("p", {}, "UA: ", c.user_agents.map((u) => `${u.user_agent} (${u.category})`).join(" · ")),
    el("p", {}, `${cap(pr.object_label_plural)} con 2xx (IDs únicos): ${fmt(c.impact.unique_invoices_2xx)} (fuera del rango normal: ${fmt(c.impact.unique_invoices_2xx_outside_baseline)})`),
    el("ul", { class: "reasons" }, c.phases.map((p) => el("li", {}, `Fase ${p.phase}: ${p.start} → ${p.end} · ${p.median_per_day}/día · éxito ${pct(p.success_ratio)}${p.constant_daily_volume ? " · volumen constante" : ""}`))),
    el("p", { class: "muted" }, `Patient zero: ${when(c.patient_zero.ts)} desde ${c.patient_zero.source_ip} (status ${c.patient_zero.status})`))));

  $("timeline").replaceChildren(...(ev.timeline || []).map((t) =>
    el("li", { class: (t.campaign_id || "").toLowerCase() }, el("div", { class: "when" }, when(t.ts), t.campaign_id ? ` · ${t.campaign_id}` : ""), t.event)));

  const io = ev.iocs || {};
  const iocTable = el("table");
  table(iocTable, ["Tipo", "Valor", "Detalle"], [
    ...(io.ips || []).map((i) => ["IP", el("span", { class: "mono" }, i.value), el("span", {}, campaignBadge(i.campaign_id), " ", levelTag(i.risk_level))]),
    ...(io.user_agents || []).map((u) => ["User agent", el("span", { class: "mono" }, u.value), `${u.category}${u.exclusive_to_attack ? " · exclusivo del ataque" : ""}`]),
    ...(io.tokens || []).map((t) => ["Token", el("span", { class: "mono" }, `${t.hint} (${t.fingerprint})`), levelTag(t.risk_level)]),
  ]);
  $("iocs").replaceChildren(el("div", { class: "table-wrap" }, iocTable),
    ...(io.enumeration_patterns || []).map((pt) => el("p", { class: "muted" }, `${pt.campaign_id}: ${pt.description}. Regla sugerida: ${pt.suggested_detection_rule}`)));

  table($("top20-table"), [{ label: "#" }, { label: "IP" }, { label: "Riesgo" }, { label: "Campaña" }, { label: "Peticiones", num: true }, { label: "2xx", num: true }, { label: cap(pr.object_label_plural), num: true }, { label: "UA principal" }, { label: "Muestra" }],
    (ev.top20_ips || []).map((t) => [t.rank, el("span", { class: "mono" }, t.ip), levelTag(t.risk_level), campaignBadge(t.campaign_id), fmt(t.requests), fmt(t.success_2xx), fmt(t.unique_invoices),
      short(t.top_user_agents?.[0]?.user_agent, 34),
      el("ul", { class: "reasons" }, (t.sample_requests || []).slice(0, 2).map((s) => el("li", {}, `${when(s.ts)} · ${s.status} · id ${s.invoice_id}`)))]));
  renderTI();
}

/* ---------------------------------------------------------------- Inteligencia de amenazas (5b) */
const VERDICT_ICON = { malicioso: "⛔", sospechoso: "▲", "sin reportes": "○", "sin datos": "–" };
const verdictTag = (v) => el("span", { class: `verdict ${v.replace(" ", "-")}` }, `${VERDICT_ICON[v] || ""} ${v}`);
const extLink = (href, text) => el("a", { href, target: "_blank", rel: "noopener noreferrer" }, text);

const LEVEL_CLASS = (lv) => (lv || "sin datos").replace(" ", "-");
const sourceLabel = (id) => state.ti?.sources.find((x) => x.id === id)?.label || id;
const STATUS_TEXT = { quota: "cupo agotado", error: "error", not_configured: "sin clave", unsupported: "no aplica", not_found: "sin registros" };

function sourceItem(src) {
  const label = sourceLabel(src.source);
  const ok = src.status === "ok" || src.status === "not_found";
  const text = ok ? (src.summary || STATUS_TEXT[src.status] || "") : (src.error || STATUS_TEXT[src.status] || src.status);
  return el("li", { class: ok ? null : "muted" },
    el("span", { class: `verdict ${LEVEL_CLASS(ok ? src.level : "sin datos")}` }, ok && src.level !== "informativo" ? VERDICT_ICON[src.level] || "" : "ⓘ"),
    ` ${label}: ${short(text, 70)}`, src.cached ? " (caché)" : "", src.permalink ? [" ", extLink(src.permalink, "↗")] : null);
}

function renderTI() {
  const ti = state.summary?.enrichment;
  $("dl-ti").hidden = !ti;
  if (ti) downloadLink("dl-ti", "enrichment/ti_enrichment.json");
  $("ti-caveat").hidden = !ti;
  $("ti-summary").hidden = !ti;
  if (!ti) { $("ti-table").replaceChildren(); $("ti-progress").textContent = "Este run aún no tiene enriquecimiento."; return; }
  if (!ti.results.length || !ti.results[0].sources) { // artefacto del formato anterior (solo VirusTotal/OTX)
    $("ti-table").replaceChildren(); $("ti-progress").textContent = "Enriquecimiento en formato anterior: vuelva a ejecutarlo."; return;
  }
  $("ti-caveat").textContent = ti.caveat;
  const st = ti.stats || {};
  $("ti-progress").textContent = `${ti.gateway || "ti-gateway"} · ${ti.sources.map(sourceLabel).join(", ")} · ${when(ti.generated_at)} · ` +
    `${st.queried} envíos a fuentes, ${st.cached} desde caché, ${st.errors} errores · ${st.seconds} s` + (ti.skipped?.length ? ` · ${ti.skipped.length} IPs privadas omitidas` : "");
  $("ti-summary").replaceChildren(...Object.entries(ti.summary).map(([k, v]) =>
    el("div", { class: "kpi" }, el("div", { class: "label" }, verdictTag(k)), el("div", { class: "value" }, fmt(v)), el("div", { class: "sub" }, `de ${ti.results.length} IPs`))));
  const net = (c) => [c.asn, c.as_name, c.country, c.usage_type, c.tor ? "Tor" : null].filter(Boolean).join(" · ") || "—";
  table($("ti-table"), [{ label: "IP" }, { label: "Campaña" }, { label: "Riesgo (logs)" }, { label: "Veredicto TI" }, { label: "Fuentes" }, { label: "Red" }, { label: "Razones" }],
    ti.results.map((r) => [el("span", { class: "mono" }, r.ip), campaignBadge(r.campaign_id), levelTag(r.risk_level),
      el("div", {}, verdictTag(r.verdict), r.possible_false_positive ? el("div", { class: "warn-text" }, "posible falso positivo") : null),
      el("ul", { class: "reasons sources" }, r.sources.filter((x) => x.status !== "unsupported").map(sourceItem)), net(r.context || {}),
      el("ul", { class: "reasons" }, (r.verdict_reasons.length ? r.verdict_reasons : ["Sin reportes en las fuentes consultadas"]).map((x) => el("li", {}, x)))]));
}

$("ti-run").addEventListener("click", async () => {
  if (!state.run) return;
  const sources = [...document.querySelectorAll("#ti-sources-pick input:checked")].map((x) => x.value);
  if (!sources.length) { $("ti-progress").textContent = "Seleccione al menos una fuente con clave configurada (pestaña Configuración)."; return; }
  if (!$("ti-consent").checked) { $("ti-progress").textContent = "Marque la autorización de envío de las IPs públicas."; $("ti-consent").focus(); return; }
  $("ti-run").disabled = true;
  $("ti-progress").textContent = sources.includes("virustotal") ? "Consultando… (API pública de VirusTotal: ~15 s por IP)" : "Consultando…";
  try {
    const { job_id } = await api(`/api/runs/${state.run}/enrich`, { method: "POST", json: { sources, consent: true } });
    followJob(job_id, (ev) => { if (["lookup", "ip_done"].includes(ev.kind)) $("ti-progress").textContent = ev.message; },
      async (job) => {
        $("ti-run").disabled = false;
        $("ti-consent").checked = false; // la autorización es por ejecución
        if (job.status === "failed") { $("ti-progress").textContent = `Error: ${job.error}`; return; }
        await selectRun(state.run);
        loadTI();
      });
  } catch (e) { $("ti-progress").textContent = e.message; $("ti-run").disabled = false; }
});

$("verify-btn").addEventListener("click", async () => {
  if (!state.run) return;
  $("verify-results").replaceChildren(el("li", {}, "Verificando…"));
  try {
    const r = await api(`/api/runs/${state.run}/verify`, { method: "POST" });
    const items = r.checks.map((c) => el("li", { class: c.ok ? null : "fail" }, c.check));
    if (!r.source_checked) items.push(el("li", { class: "fail" }, "Archivo original no encontrado en data/ (no se re-verificó su hash)"));
    $("verify-results").replaceChildren(...items);
  } catch (e) { alertMsg(e); }
});

/* ---------------------------------------------------------------- 4 · Agentes */
const AGENT_STEPS = [["triage", "Triage"], ["forensic", "Forensic"], ["response", "Response"], ["policy", "Política"],
  ["human_review", "Aprobación humana"], ["execute", "Dry-run"], ["report", "Informe"]];

function renderStepper(done, active, waiting = false) {
  $("agent-stepper").replaceChildren(...AGENT_STEPS.map(([k, label]) =>
    el("li", { class: done.has(k) ? "done" : k === active ? (waiting ? "wait" : "active") : null }, label)));
}

/* Transparencia (mejora O13, punto 12): estado de la revisión y qué agregó o corrigió el código. */
function checksBox(checks) {
  if (!checks) return null;
  const ok = checks.status !== "con observaciones";
  const items = [
    ...(checks.issues || []).map((x) => el("li", { class: "warn-text" }, `⚠ ${x}`)),
    ...(checks.corrections || []).map((x) => el("li", {}, `✎ ${x}`)),
    ...(checks.code_additions || []).map((x) => el("li", { class: "muted" }, `⚙ ${x}`)),
  ];
  return el("details", { class: "checks" },
    el("summary", {}, el("span", { class: `badge ${ok ? "ok" : "warn"}` }, ok ? "✓ verificado" : `⚠ con observaciones (${checks.issues.length})`),
      ` ${(checks.corrections || []).length} corregidas · ${(checks.code_additions || []).length} fijadas por el código`),
    el("ul", { class: "reasons" }, items));
}
function agentCard(title, entry, body, checks) {
  const fix = entry?.fix_calls ? ` · ${entry.fix_calls} correcciones (${entry.fix_latency_s} s)` : "";
  const meta = entry ? `fuente: ${entry.source}${entry.latency_s != null ? ` · ${entry.latency_s} s` : ""}${fix}` : "";
  return el("div", { class: "card agent-card" }, el("h2", {}, title), el("div", { class: "meta" }, meta),
    entry?.error ? el("div", { class: "warn-text" }, `Fallback: ${entry.error}`) : null,
    checksBox(checks),
    body);
}
const KIND_BADGE = { hecho: ["ok", "hecho"], hipotesis: ["warn", "hipótesis"] };
function hypothesisItem(h) {
  const [cls, label] = KIND_BADGE[h.kind] || ["", h.kind];
  return el("li", {}, el("span", { class: `badge ${cls}` }, label), " ", h.text, h.origin === "código" ? el("span", { class: "muted small" }, " (agregada por el código)") : null);
}
function mitreItem(t) {
  const src = t.source === "regla (evidencia)" ? el("span", { class: "badge warn" }, "obligatoria · agregada por regla")
    : t.required ? el("span", { class: "badge ok" }, "obligatoria · elegida por el modelo") : el("span", { class: "badge" }, "elegida por el modelo");
  return el("li", {}, el("a", { href: t.url || "https://attack.mitre.org", target: "_blank", rel: "noopener noreferrer" }, `${t.technique_id} ${t.name}`),
    ` · ${t.tactic} `, src, el("div", { class: "muted small" },
      `${t.justification}${t.justification_source === "código" ? " (justificación generada con la evidencia)" : ""}${t.rule ? ` · regla: ${t.rule}` : ""}`));
}

function renderAgents() {
  const s = state.summary, rep = s.agents;
  ["dl-playbook:agents/playbook.md", "dl-agents:agents/agents_report.json", "dl-log:agents/decision_log.jsonl"].forEach((x) => downloadLink(...x.split(":")));
  if (!rep) {
    renderStepper(new Set(), null);
    $("agents-result").replaceChildren(el("div", { class: "card" }, el("p", { class: "muted" }, "Aún no se han ejecutado los agentes para este run.")));
    ["actions-table", "decision-table"].forEach((id) => $(id).replaceChildren());
    $("playbook").replaceChildren(); $("times").replaceChildren();
    return;
  }
  renderStepper(new Set(AGENT_STEPS.map(([k]) => k)), null);
  const log = Object.fromEntries((s.decision_log || []).map((e) => [e.node, e]));
  const tri = rep.triage || {}, fo = rep.forensic || {}, ro = rep.response || {};
  $("agents-msg").textContent = `Última ejecución: ${rep.llm} · ${rep.agents_seconds} s`;
  $("agents-result").replaceChildren(
    agentCard("Triage", log.triage, el("div", {},
      el("p", {}, levelTag(tri.severity), ` · ${tri.attack_type} · confianza ${pct(tri.confidence)}`),
      tri.confidence_basis?.length ? el("p", { class: "muted small" }, `Confianza calculada por el código: ${tri.confidence_basis.join("; ")}. ${tri.severity_basis || ""}`) : null,
      el("h3", {}, "Hipótesis"),
      el("ul", { class: "plain" }, (tri.hypotheses_detail?.length ? tri.hypotheses_detail.map(hypothesisItem) : (tri.hypotheses || []).map((h) => el("li", {}, h)))),
      tri.priority_targets?.length ? el("p", {}, el("strong", {}, "Prioridad (por campaña): "), tri.priority_targets.join(" → ")) : null,
      el("h3", {}, "Plan"), el("ul", {}, (tri.investigation_plan || []).map((h) => el("li", {}, h)))), tri.checks),
    agentCard("Forensic Analyst", log.forensic, el("div", {},
      el("p", {}, fo.attack_pattern),
      el("h3", {}, "Razonamiento"), el("ul", {}, (fo.reasoning || []).map((h) => el("li", {}, h))),
      el("p", { class: "muted" }, `Patient zero (evidencia): ${fo.patient_zero}`),
      el("p", { class: "muted" }, `Inicio (evidencia): ${fo.exploitation_start}`),
      fo.automation_type ? el("p", { class: "muted" }, `Automatización (evidencia): ${fo.automation_type}`) : null,
      el("p", {}, fo.campaigns_assessment || ""),
      el("h3", {}, "MITRE ATT&CK"),
      el("ul", { class: "plain" }, (fo.mitre_attack || []).map(mitreItem))), fo.checks),
    agentCard("Response Advisor", log.response, el("div", {},
      el("p", {}, ro.ordering_rationale),
      el("p", { class: "muted" }, `${(ro.actions || []).length} acciones · ${(ro.actions || []).filter((a) => a.added_by_policy).length} agregadas por política · ${(rep.policy_overrides || []).length} endurecidas por la política`)), ro.checks),
  );
  const executed = new Map((rep.executed || []).map((e) => [e.action_id, e]));
  const artifactLink = (e) => el("a", { class: "small", href: `/api/runs/${state.run}/download/agents/${e.artifact}`, title: "Artefacto dry-run (no aplicado)" }, "ver artefacto");
  table($("actions-table"), ["ID", "Tipo", "Fase", "Prioridad", "Objetivo", "Origen", "Riesgo FP", "Impacto", "Aprobación", "Resultado"],
    (ro.actions || []).map((a) => [a.action_id, a.action_type, a.phase, a.priority, a.target,
      a.added_by_policy ? el("span", { class: "badge warn" }, "agregada por política") : el("span", { class: "muted small" }, a.mandatory ? `modelo · obligatoria (${a.reason_required})` : "modelo"),
      a.false_positive_risk, a.business_impact,
      a.requires_human_approval ? `humana → ${rep.approvals?.[a.action_id] || "—"}` : "automática",
      executed.has(a.action_id) ? el("span", { class: "result-cell" }, el("span", { class: "badge ok" }, "ejecutada (dry-run)"), artifactLink(executed.get(a.action_id))) : el("span", { class: "badge warn" }, "no ejecutada")]));
  $("playbook").replaceChildren(...(ro.playbook || []).map((p) => el("li", {}, p)));
  const est = rep.response_time_estimates || {};
  const bt = est.detection_backtest || {};
  $("times").replaceChildren(
    el("p", {}, `TTD ${est.ttd_is_estimate ? "estimado (hasta el último registro del log; indique la fecha de detección para medirlo)" : "medido"}: ${est.ttd_days_measured} días (desde el primer acceso: ${est.ttd_from_first_success_days_measured})`),
    el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, ""), el("th", { class: "num" }, "Manual (supuesto)"), el("th", { class: "num" }, "Automatizado"), el("th", { class: "num" }, "Reducción"))),
      el("tbody", {},
        el("tr", {}, el("td", {}, "TTR"), el("td", { class: "num" }, `${est.manual?.ttr_hours} h`), el("td", { class: "num" }, `${est.automated?.ttr_hours} h`), el("td", { class: "num" }, `${est.reduction?.ttr_percent} %`)),
        el("tr", {}, el("td", {}, "TTC"), el("td", { class: "num" }, `${est.manual?.ttc_hours} h`), el("td", { class: "num" }, `${est.automated?.ttc_hours} h`), el("td", { class: "num" }, `${est.reduction?.ttc_percent} %`)))),
    el("h3", {}, "Backtest de reglas de detección"),
    el("ul", { class: "reasons" }, Object.values(bt).map((r) => el("li", {}, `${r.rule}: habría alertado ${when(r.would_alert_on)} (otros tokens alertados: ${r.other_tokens_alerted})`))),
    el("p", { class: "muted" }, est.note || ""));
  table($("decision-table"), ["Hora (UTC)", "Nodo", "Fuente", "Latencia", "Decisión"],
    (s.decision_log || []).map((e) => [when(e.ts), e.node, e.source, e.latency_s != null ? `${e.latency_s} s` : "—", e.error ? `${e.decision} — ${e.error}` : e.decision]));
}

$("agents-btn").addEventListener("click", async () => {
  if (!state.run) return;
  const useLlm = $("use-llm").checked;
  const active = activeProvider();
  if (useLlm && active?.off_lan && !$("cloud-consent").checked) {
    $("consent-box").hidden = false;
    $("agents-msg").textContent = `Para usar ${active.label}, marque la autorización de envío del contexto agregado (o desmarque "Usar LLM").`;
    $("agents-msg").className = "warn-text";
    $("cloud-consent").focus();
    return;
  }
  $("agents-msg").className = "muted";
  $("agents-btn").disabled = true;
  const done = new Set();
  renderStepper(done, "triage");
  $("agents-msg").textContent = useLlm && active?.kind === "ollama"
    ? "Ejecutando… (Ollama en CPU puede tardar varios minutos)" : "Ejecutando…";
  try {
    const { job_id } = await api(`/api/runs/${state.run}/agents`, { method: "POST", json: { use_llm: useLlm, cloud_consent: $("cloud-consent").checked } });
    state.agentsJob = job_id;
    followJob(job_id, async (ev) => {
      const idx = AGENT_STEPS.findIndex(([k]) => k === ev.kind);
      if (idx >= 0) { done.add(ev.kind); renderStepper(done, AGENT_STEPS[idx + 1]?.[0]); $("agents-msg").textContent = `${ev.kind}: ${ev.message}`; }
      if (ev.kind === "info") $("agents-msg").textContent = ev.message;
      if (ev.kind === "awaiting_approval") { renderStepper(done, "human_review", true); await showApprovals(job_id); }
    }, async (job) => {
      $("agents-btn").disabled = false;
      $("approval-box").hidden = true;
      if (job.status === "failed") { $("agents-msg").textContent = `Error: ${job.error}`; return; }
      await loadRuns(state.run);
    });
  } catch (e) { alertMsg(e); $("agents-btn").disabled = false; }
});

/* Panel de aprobación: las pendientes llevan selector (por defecto Rechazar); las automáticas se muestran sin
   selector para que el analista vea el plan completo y el criterio de automatización. */
function actionSummary(a) {
  return el("div", {}, el("strong", {}, `${a.action_id} · ${a.action_type}`), ` (${a.phase}, prioridad ${a.priority})`,
    el("div", { class: "muted" }, a.target),
    el("div", { class: "muted" }, `${a.rationale} · FP ${a.false_positive_risk} · impacto ${a.business_impact}`));
}
async function showApprovals(jobId) {
  const job = await api(`/api/jobs/${jobId}`);
  const pending = job.pending_actions || [];
  const automatic = job.automatic_actions || [];
  const items = [
    el("h4", {}, `Requieren su decisión (${pending.length}) · por defecto: Rechazar`),
    ...pending.map((a) => el("div", { class: "approval-item" }, actionSummary(a),
      el("select", { dataset: { action: a.action_id }, "aria-label": `Decisión ${a.action_id}` },
        el("option", { value: "reject" }, "Rechazar"), el("option", { value: "approve" }, "Aprobar")))),
  ];
  if (automatic.length) {
    items.push(
      el("h4", {}, `Automáticas (${automatic.length}) · se ejecutan sin aprobación`),
      el("p", { class: "muted small" }, "Cumplen las tres condiciones de la política: reversibles, riesgo de falso positivo bajo e impacto de negocio bajo. Se generan en dry-run aunque rechace todas las demás."),
      ...automatic.map((a) => el("div", { class: "approval-item auto" }, actionSummary(a),
        el("span", { class: "badge ok" }, "Automática"))),
    );
  }
  $("approval-list").replaceChildren(...items);
  $("approval-box").hidden = false;
}
$("approve-all").addEventListener("click", () => document.querySelectorAll("#approval-list select").forEach((s) => (s.value = "approve")));
$("reject-all").addEventListener("click", () => document.querySelectorAll("#approval-list select").forEach((s) => (s.value = "reject")));
$("submit-approvals").addEventListener("click", async () => {
  const decisions = {};
  document.querySelectorAll("#approval-list select").forEach((s) => (decisions[s.dataset.action] = s.value));
  try {
    await api(`/api/jobs/${state.agentsJob}/approvals`, { method: "POST", json: { decisions } });
    $("approval-box").hidden = true;
    $("agents-msg").textContent = "Decisiones enviadas; ejecutando dry-run…";
  } catch (e) { alertMsg(e); }
});

/* ---------------------------------------------------------------- 5 · Configuración */
function kv(node, pairs) { node.replaceChildren(...pairs.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])); }
async function loadConfig() {
  const c = await api("/api/config");
  state.config = c;
  $("upload-limit").textContent = c.max_upload_mb;
  const p = c.profile || {};
  const fixed = c.profile_mode === "fixed";
  kv($("analysis-config"), [
    ["Perfil del incidente", fixed ? "fijo (IRP_PROFILE_MODE=fixed): se usan los valores de abajo" : "detección automática en cada análisis"],
    [fixed ? "Endpoint objetivo" : "Endpoint de respaldo", p.target_endpoint],
    ["Parámetros" + (fixed ? "" : " de respaldo"), [p.object_param, p.scope_param, p.token_param].filter(Boolean).join(" · ")],
    ["Formato de fecha", c.timestamp_format || "automático"],
    ["Fecha de detección", c.detection_date ? when(c.detection_date) : "no definida (se indica en cada análisis)"],
    ["Autenticación", c.auth_enabled ? "token requerido" : "desactivada (solo localhost)"]]);
  $("pf-detection_date").value = (c.detection_date || "").slice(0, 10);
  if (!state.summary?.manifest) fillProfileForm();
  setManual(false);
}

/* Proveedor LLM: el formulario edita el proveedor SELECCIONADO; "Usar para los agentes" lo activa. */
const activeProvider = () => state.llm?.providers.find((p) => p.id === state.llm.active);
const selectedProvider = () => state.llm?.providers.find((p) => p.id === $("llm-provider").value);

function renderLlm(llmState, keepSelection = true) {
  state.llm = llmState;
  const sel = $("llm-provider");
  const current = keepSelection && sel.value ? sel.value : llmState.active;
  const group = (label, items) => el("optgroup", { label }, ...items.map((p) =>
    el("option", { value: p.id }, `${p.label}${p.id === llmState.active ? "  ✓ activo" : ""}`)));
  sel.replaceChildren(
    group("Local / red interna", llmState.providers.filter((p) => !p.cloud)),
    group("API en la nube", llmState.providers.filter((p) => p.cloud)));
  sel.value = current;
  fillLlmForm();
  const a = activeProvider();
  $("llm-active").textContent = a ? `Activo: ${a.label} · ${a.model || "sin modelo"}` : "";
  $("agents-llm").textContent = a ? `${a.label} · ${a.model || "sin modelo"}` : "—";
  $("consent-provider").textContent = a?.label || "";
  $("consent-box").hidden = !(a?.off_lan);
  if (!a?.off_lan) $("cloud-consent").checked = false;
  renderChatLlm();
}

/* Conversación: proveedor y modelo propios (iguales o distintos a los de los agentes). */
const chatCfg = () => state.llm?.chat || {};
function renderChatLlm() {
  const c = chatCfg(), a = activeProvider();
  const sel = $("chatllm-provider");
  const keep = sel.dataset.touched ? sel.value : (c.provider || "");
  sel.replaceChildren(el("option", { value: "" }, `Igual que los agentes (${a?.label || "—"})`),
    ...state.llm.providers.map((p) => el("option", { value: p.id }, `${p.label}${p.needs_key ? (p.key_configured ? "  · clave ✓" : "  · requiere API key") : ""}`)));
  sel.value = keep;
  if (!sel.dataset.touched) $("chatllm-model").value = c.model || "";
  fillChatProviderFields();
  $("chatllm-state").textContent = `En uso: ${c.effective_label} · ${c.effective_model || "sin modelo"}${c.off_lan ? " · nube: se pedirá autorización en el chat" : ""}${c.ready ? "" : " · ⚠ falta configurar"}`;
}
/* Campos de URL y API key del proveedor elegido para la conversación (se guardan en ESE proveedor). */
const chatProvider = () => state.llm?.providers.find((p) => p.id === ($("chatllm-provider").value || state.llm.active));
function fillChatProviderFields() {
  const p = chatProvider();
  if (!p) return;
  $("chatllm-help").textContent = $("chatllm-provider").value ? p.help : `Usa el proveedor de los agentes: ${p.label}.`;
  const showKey = Boolean($("chatllm-provider").value) && (p.needs_key || p.key_optional);
  $("chatllm-key-row").hidden = !showKey;
  $("chatllm-key").value = "";
  $("chatllm-key-state").textContent = p.key_configured ? `(configurada ${p.key_hint}; pegue otra para reemplazarla)` : p.needs_key ? "(requerida)" : "(opcional)";
  const showUrl = Boolean($("chatllm-provider").value) && p.base_url_editable;
  $("chatllm-url-row").hidden = !showUrl;
  $("chatllm-url").value = p.base_url || "";
}
async function saveChatProviderCreds() {
  const p = chatProvider();
  if (!p || !$("chatllm-provider").value) return;
  const body = { provider: p.id };
  const key = $("chatllm-key").value.trim();
  if (key) body.api_key = key;
  if (p.base_url_editable && $("chatllm-url").value.trim() && $("chatllm-url").value.trim() !== p.base_url) body.base_url = $("chatllm-url").value.trim();
  $("chatllm-key").value = ""; // la clave no permanece en el DOM
  if (Object.keys(body).length > 1) {
    const st = await api("/api/llm/config", { method: "POST", json: body });
    const touched = $("chatllm-provider").dataset.touched;
    renderLlm(st);
    if (touched) $("chatllm-provider").dataset.touched = touched;
  }
}
$("chatllm-provider").addEventListener("change", (e) => { e.target.dataset.touched = "1"; $("chatllm-models").replaceChildren(); $("chatllm-count").textContent = ""; fillChatProviderFields(); });
$("chatllm-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const provider = $("chatllm-provider").value, model = $("chatllm-model").value.trim();
    await saveChatProviderCreds();
    $("chatllm-provider").value = provider; $("chatllm-model").value = model;
    const st = await api("/api/llm/chat", { method: "POST", json: { provider: $("chatllm-provider").value || null, model: $("chatllm-model").value.trim() } });
    delete $("chatllm-provider").dataset.touched;
    renderLlm(st);
    $("chatllm-results").replaceChildren(el("li", {}, `Conversación: ${st.chat.effective_label} · ${st.chat.effective_model}`));
  } catch (err) { $("chatllm-results").replaceChildren(el("li", { class: "fail" }, err.message)); }
});
const chatProviderId = () => $("chatllm-provider").value || state.llm?.active;
$("chatllm-list").addEventListener("click", async () => {
  try {
    await saveChatProviderCreds();
    const r = await api("/api/llm/models", { method: "POST", json: { provider: chatProviderId() } });
    $("chatllm-models").replaceChildren(...r.models.map((m) => el("option", { value: m })));
    $("chatllm-count").textContent = `(${r.models.length} disponibles)`;
  } catch (err) { $("chatllm-results").replaceChildren(el("li", { class: "fail" }, err.message)); }
});
$("chatllm-test").addEventListener("click", async () => {
  $("chatllm-results").replaceChildren(el("li", {}, "Probando…"));
  try {
    await saveChatProviderCreds();
    const r = await api("/api/llm/test", { method: "POST", json: { provider: chatProviderId(), model: $("chatllm-model").value.trim() || null } });
    $("chatllm-results").replaceChildren(...r.checks.map((c) => el("li", { class: c.ok ? null : "fail" }, c.check)));
  } catch (err) { $("chatllm-results").replaceChildren(el("li", { class: "fail" }, err.message)); }
});

function fillLlmForm() {
  const p = selectedProvider();
  if (!p) return;
  $("llm-help").textContent = p.help;
  $("llm-url").value = p.base_url;
  $("llm-url").readOnly = !p.base_url_editable;
  $("llm-key-row").hidden = !(p.needs_key || p.key_optional);
  $("llm-key").value = "";
  $("llm-key-state").textContent = p.key_configured ? `(configurada ${p.key_hint})` : p.needs_key ? "(requerida)" : "(opcional)";
  $("llm-key-clear").hidden = !p.key_configured;
  $("llm-model").value = p.model || "";
  $("llm-models").replaceChildren();
  $("llm-models-count").textContent = "";
  $("llm-cloud-warn").hidden = !p.off_lan;
  $("llm-results").replaceChildren();
}

async function saveLlm(extra = {}) {
  const p = selectedProvider();
  const body = { provider: p.id, model: $("llm-model").value.trim(), ...extra };
  if (p.base_url_editable) body.base_url = $("llm-url").value.trim();
  const key = $("llm-key").value.trim();
  if (key) body.api_key = key;
  $("llm-key").value = ""; // la clave no permanece en el DOM
  const llmState = await api("/api/llm/config", { method: "POST", json: body });
  renderLlm(llmState);
  return llmState;
}

function llmResults(items) {
  $("llm-results").replaceChildren(...items.map(([ok, text]) => el("li", { class: ok ? null : "fail" }, text)));
}

$("llm-provider").addEventListener("change", fillLlmForm);
$("llm-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { await saveLlm(); llmResults([[true, "Configuración guardada"]]); } catch (err) { llmResults([[false, err.message]]); }
});
$("llm-key-clear").addEventListener("click", async () => {
  try { await saveLlm({ clear_key: true }); llmResults([[true, "Clave eliminada de la memoria del servidor"]]); } catch (err) { llmResults([[false, err.message]]); }
});
$("llm-list").addEventListener("click", async () => {
  llmResults([[true, "Consultando modelos…"]]);
  try {
    await saveLlm();
    const p = selectedProvider();
    const r = await api("/api/llm/models", { method: "POST", json: { provider: p.id } });
    $("llm-models").replaceChildren(...r.models.map((m) => el("option", { value: m })));
    $("llm-models-count").textContent = `(${r.models.length} disponibles)`;
    llmResults([[r.models.length > 0, r.models.length ? `${r.models.length} modelos: haga clic en el campo Modelo para elegir` : "El proveedor no devolvió modelos; escriba el nombre manualmente"]]);
    if (!$("llm-model").value && r.models.length) $("llm-model").focus();
  } catch (err) { llmResults([[false, err.message]]); }
});
$("llm-activate").addEventListener("click", async () => {
  try {
    await saveLlm({ activate: true });
    llmStatus();
    llmResults([[true, `${selectedProvider().label} queda activo para los agentes`]]);
  } catch (err) { llmResults([[false, err.message]]); }
});
$("llm-test").addEventListener("click", async () => {
  llmResults([[true, "Probando… (Ollama en CPU puede tardar ~1 min)"]]);
  try {
    await saveLlm();
    const r = await api("/api/llm/test", { method: "POST", json: { provider: selectedProvider().id } });
    llmResults([...r.checks.map((c) => [c.ok, c.check]), ...(r.seconds !== undefined ? [[r.ok, `${r.seconds} s`]] : [])]);
  } catch (err) { llmResults([[false, err.message]]); }
});

async function llmStatus() {
  const pill = $("llm-status");
  try {
    const r = await api("/api/llm/status");
    const name = `${r.label}${r.model ? ` · ${short(r.model, 28)}` : ""}`;
    if (!r.ready) { pill.textContent = `LLM ○ ${r.label}: falta configurar`; pill.className = "pill bad"; return; }
    if (r.reachable === false) { pill.textContent = `LLM ○ ${name} sin conexión`; pill.className = "pill bad"; return; }
    pill.textContent = `LLM ● ${name}${r.off_lan ? " (nube)" : ""}`;
    pill.className = "pill ok";
  } catch { pill.textContent = "LLM ○ error"; pill.className = "pill bad"; }
}
/* Fuentes TI: el catálogo viene del servidor MCP ti-gateway; las claves son solo de escritura. */
const PERIOD = { day: "día", week: "semana", month: "mes" };
function renderTIConfig(t) {
  state.ti = t;
  const rows = t.sources.map((x) => {
    const keyState = x.key_configured ? `configurada ${x.key_hint}${x.origin === "entorno" ? " (entorno)" : ""}` : x.key_required ? "requerida" : "opcional";
    const quota = x.quota_period ? `${x.quota_used} de ${x.quota_limit ?? "∞"} por ${PERIOD[x.quota_period]}` : "sin cupo fijo";
    return [
      el("div", {}, el("strong", {}, x.label), x.publishes_queries ? el("div", { class: "warn-text" }, "⚠ publica lo consultado") : null,
        el("div", { class: "muted small" }, x.terms_note, " ", extLink(x.docs_url, "términos ↗"))),
      x.indicator_types.join(" · "),
      el("div", { class: "keycell" },
        x.needs_url ? el("label", { class: "small field" }, el("span", {}, "URL de la instancia ", el("span", { class: "muted" }, "(interna o externa)")),
          el("input", { type: "url", maxlength: "300", spellcheck: "false", placeholder: x.url_placeholder || "https://misp.suempresa.com",
            value: x.base_url || "", dataset: { tiUrl: x.id, orig: x.base_url || "" }, "aria-label": `URL de la instancia de ${x.label}` }),
          el("span", { class: x.base_url ? "muted" : "warn-text" }, x.base_url ? "configurada" : "requerida: sin URL la fuente no se usa")) : null,
        x.needs_url ? el("label", { class: "small field" }, el("span", {}, "Certificado TLS ", el("span", { class: "muted" }, "(opcional: autofirmado o CA interna, PEM)")),
          el("textarea", { rows: "2", maxlength: "30000", spellcheck: "false", placeholder: "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
            dataset: { tiCa: x.id }, "aria-label": `Certificado TLS de ${x.label}` }),
          el("span", { class: "muted" }, x.ca_fingerprint ? `cargado · SHA-256 ${x.ca_fingerprint}` : "sin certificado propio (se usa el almacén del sistema)")) : null,
        x.needs_url ? el("label", { class: "check small" },
          el("input", { type: "checkbox", checked: x.tls_verify === false, dataset: { tiInsecure: x.id, orig: String(x.tls_verify === false) } }),
          " Omitir la verificación del certificado TLS ", el("span", { class: "muted" }, "(solo instancias en la red interna)")) : null,
        x.needs_url && x.tls_verify === false ? el("span", { class: "warn-text small" },
          "⚠ TLS sin verificar: el tráfico sigue cifrado, pero no se comprueba la identidad del servidor (riesgo de suplantación). Úselo solo en laboratorio; queda en la cadena de custodia.") : null,
        el("label", { class: "small field" }, el("span", {}, "API key ", el("span", { class: "muted" }, `(${keyState})`)),
          el("input", { type: "password", maxlength: "512", autocomplete: "new-password", spellcheck: "false", placeholder: "pegar clave…",
            dataset: { tiKey: x.id }, "aria-label": `API key de ${x.label}` }))),
      el("div", { class: "limits" },
        el("label", { class: "small" }, "por min ", el("input", { type: "number", min: "1", max: "10000", value: String(x.per_minute), dataset: { tiRpm: x.id, orig: String(x.per_minute) }, "aria-label": `Consultas por minuto de ${x.label}` })),
        x.quota_period ? el("label", { class: "small" }, `cupo/${PERIOD[x.quota_period]} `, el("input", { type: "number", min: "0", max: "10000000", value: String(x.quota_limit ?? ""), dataset: { tiQuota: x.id, orig: String(x.quota_limit ?? "") }, "aria-label": `Cupo de ${x.label}` })) : null,
        el("div", { class: "muted small" }, quota)),
      el("div", { class: "row" },
        el("button", { type: "button", class: "btn ghost small", dataset: { tiTest: x.id } }, "Validar"),
        x.key_configured ? el("button", { type: "button", class: "btn ghost small", dataset: { tiClear: x.id } }, "Olvidar") : null,
        x.ca_fingerprint ? el("button", { type: "button", class: "btn ghost small", dataset: { tiCaClear: x.id } }, "Quitar certificado") : null),
    ];
  });
  table($("ti-sources-table"), [{ label: "Fuente" }, { label: "Indicadores" }, { label: "Conexión" }, { label: "Ritmo y cupo" }, { label: "" }], rows);
  const previous = new Set([...document.querySelectorAll("#ti-sources-pick input:checked")].map((x) => x.value));
  $("ti-sources-pick").replaceChildren(...t.sources.map((x) => el("label", { class: "check" },
    el("input", { type: "checkbox", value: x.id, disabled: !x.usable, checked: x.usable && (previous.size ? previous.has(x.id) : x.key_configured) }),
    `${x.label}${x.publishes_queries ? " ⚠" : ""}`)));
  const usable = t.sources.filter((x) => x.usable).map((x) => x.label);
  $("ti-sources-hint").textContent = usable.length ? `Disponibles: ${usable.join(", ")}. ⚠ = publica lo consultado.` : "Configure al menos una API key (y la URL en fuentes autoalojadas como MISP) en la pestaña Configuración.";
}
async function loadTI() {
  try { renderTIConfig(await api("/api/ti")); } catch (e) { tiResults([[false, `ti-gateway: ${e.message}`]]); }
}
const tiResults = (items) => $("ti-results").replaceChildren(...items.map(([ok, t]) => el("li", { class: ok ? null : "fail" }, t)));
function collectTI() {
  const body = { keys: {}, per_minute: {}, quota: {}, urls: {}, ca_pems: {}, tls_insecure: {} };
  document.querySelectorAll("[data-ti-insecure]").forEach((i) => { if (String(i.checked) !== i.dataset.orig) body.tls_insecure[i.dataset.tiInsecure] = i.checked; });
  document.querySelectorAll("[data-ti-ca]").forEach((i) => { if (i.value.trim()) body.ca_pems[i.dataset.tiCa] = i.value.trim(); i.value = ""; });
  document.querySelectorAll("[data-ti-url]").forEach((i) => { if (i.value.trim() !== i.dataset.orig) body.urls[i.dataset.tiUrl] = i.value.trim(); });
  document.querySelectorAll("[data-ti-key]").forEach((i) => { if (i.value.trim()) body.keys[i.dataset.tiKey] = i.value.trim(); i.value = ""; });
  document.querySelectorAll("[data-ti-rpm]").forEach((i) => { if (i.value && i.value !== i.dataset.orig) body.per_minute[i.dataset.tiRpm] = Number(i.value); });
  document.querySelectorAll("[data-ti-quota]").forEach((i) => { if (i.value !== "" && i.value !== i.dataset.orig) body.quota[i.dataset.tiQuota] = Number(i.value); });
  return body;
}
async function saveTI(extra = {}) { renderTIConfig(await api("/api/ti/config", { method: "POST", json: { ...collectTI(), ...extra } })); }
$("ti-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { await saveTI(); tiResults([[true, "Cambios guardados (claves solo en memoria)"]]); } catch (err) { tiResults([[false, err.message]]); }
});
$("ti-sources-table").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  try {
    if (btn.dataset.tiCaClear) { await saveTI({ ca_pems: { [btn.dataset.tiCaClear]: "" } }); tiResults([[true, `Certificado de ${sourceLabel(btn.dataset.tiCaClear)} eliminado`]]); }
    if (btn.dataset.tiClear) { await saveTI({ clear: [btn.dataset.tiClear] }); tiResults([[true, `Clave de ${sourceLabel(btn.dataset.tiClear)} eliminada de la memoria`]]); }
    if (btn.dataset.tiTest) {
      const id = btn.dataset.tiTest;
      tiResults([[true, `Validando ${sourceLabel(id)}…`]]);
      await saveTI();
      const r = await api("/api/ti/test", { method: "POST", json: { source: id } });
      tiResults([[r.ok, r.detail]]);
      loadTI();
    }
  } catch (err) { tiResults([[false, err.message]]); }
});

/* ---------------------------------------------------------------- Evaluación del modelo local (O13, 10-11) */
async function loadEvaluations() {
  if (!state.run) return;
  const ev = await api(`/api/runs/${state.run}/evaluations`);
  const o = state.llm?.providers.find((p) => p.id === "ollama");
  const c = chatCfg();
  const chatLocal = c.effective_provider === "ollama" ? c.effective_model : null;
  if (!$("eval-models").value) $("eval-models").value = [o?.model, chatLocal].filter(Boolean).filter((m, i, a) => a.indexOf(m) === i).join(", ");
  table($("eval-table"), ["Modelo", "Fecha", { label: "Puntaje", num: true }, { label: "Agentes", num: true }, { label: "s agentes", num: true },
    { label: "Chat", num: true }, { label: "Dato", num: true }, { label: "Criterio", num: true }, { label: "s/pregunta", num: true }, { label: "t/s", num: true }, { label: "Observ.", num: true }, ""],
    ev.reports.map((r) => [r.modelo, when(r.fecha), r.puntaje ?? "—", r.agentes ?? "—", r.agentes_s ?? "—", r.chat ?? "—", r.chat_dato ?? "—",
      r.chat_criterio ?? "—", r.chat_s_prom ?? "—", r.tokens_s ?? "—", r.observaciones,
      el("span", {}, el("a", { href: `/api/runs/${state.run}/evaluations/${r.file.split("/")[1]}`, class: "btn ghost small" }, "json"), " ",
        el("a", { href: `/api/runs/${state.run}/evaluations/${r.file.split("/")[1].replace(/\.json$/, ".md")}`, class: "btn ghost small" }, "md"))]));
  const q = ev.latest?.chat?.questions || [];
  $("eval-detail").replaceChildren(...(q.length ? [el("h3", {}, `Última evaluación del chat (${ev.latest.model})`),
    el("div", { class: "table-wrap" }, (() => { const t = el("table"); table(t, ["#", "Agente", "Tipo", "Pregunta", { label: "Puntaje", num: true }, "Faltó", "Observaciones"],
      q.map((x) => [x.id, x.agent, x.kind, x.text, x.score, x.missing.join("; ") || "—", [...x.review_issues, ...x.forbidden_hits].join("; ") || "—"])); return t; })())] : []));
}
$("eval-btn").addEventListener("click", async () => {
  if (!state.run) return;
  const models = $("eval-models").value.split(",").map((m) => m.trim()).filter(Boolean);
  const limit = Number($("eval-limit").value) || null;
  $("eval-btn").disabled = true;
  $("eval-progress").textContent = "Iniciando…";
  try {
    const { job_id } = await api(`/api/runs/${state.run}/evaluations`, { method: "POST", json: { models, chat: $("eval-chat").checked, agents: $("eval-agents").checked, limit } });
    followJob(job_id, (ev) => { if (ev.message) $("eval-progress").textContent = ev.message; }, async (job) => {
      $("eval-btn").disabled = false;
      $("eval-progress").textContent = job.status === "completed" ? "Evaluación terminada." : `Falló: ${job.error || ""}`;
      await loadEvaluations();
    });
  } catch (e) { $("eval-btn").disabled = false; $("eval-progress").textContent = e.message; }
});

/* ---------------------------------------------------------------- 5 · Conversación con los agentes */
const CHAT_AGENTS = [
  ["triage", "Triage Agent", "Severidad, alcance y priorización"],
  ["forensic", "Forensic Analyst", "Cómo ocurrió: timeline, patient zero, MITRE"],
  ["response", "Response Advisor", "Contención, aprobaciones y playbook"],
];
state.chatAgent = "triage";
state.chatBusy = false;

function chatMessage(role, text, meta) {
  return el("div", { class: `msg ${role}` }, text, meta ? el("span", { class: "meta" }, meta) : null);
}
/* Medición por respuesta: dónde se va el tiempo (leer el prompt vs escribir) y si se reutilizó la caché. */
function statsText(st) {
  if (!st) return "";
  const parts = [];
  if (st.ttft_s != null) parts.push(`primera palabra a los ${st.ttft_s} s`);
  if (st.prompt_tokens != null) {
    const read = st.prompt_s != null ? ` en ${st.prompt_s} s` : "";
    // (con caché Ollama informa el total del prompt, pero lo "lee" en segundos: eso es lo que marca ♻)
    const cached = st.cached_tokens ? ` (${fmt(st.cached_tokens)} en caché)` : "";
    parts.push(`leyó ${fmt(st.prompt_tokens)} tokens${read}${cached}`);
  }
  if (st.cache_hit) parts.push("♻ contexto reutilizado de la caché");
  if (st.output_tokens != null) parts.push(`escribió ${fmt(st.output_tokens)} tokens${st.gen_s != null ? ` en ${st.gen_s} s` : ""}${st.tokens_per_s ? ` (${st.tokens_per_s} t/s)` : ""}`);
  if (st.load_s >= 1) parts.push(`carga del modelo ${st.load_s} s`);
  if (st.done_reason === "length") parts.push("⚠ cortada por el tope de longitud: pida que continúe");
  return parts.join(" · ");
}
function turnMeta(r) {
  if (r.source === "evidencia") return "respuesta exacta desde la evidencia (código, sin modelo) · instantánea";
  const warn = r.unverified_numbers?.length ? ` · ⚠ cifras no presentes en la evidencia: ${r.unverified_numbers.join(", ")}` : "";
  const st = statsText(r.stats);
  const ok = r.review && !r.review.issues?.length ? " · ✓ revisión automática sin observaciones" : "";
  return `${r.model} · ${r.seconds} s${r.off_lan ? " · nube (autorizado)" : ""}${st ? ` · ${st}` : ""}${warn}${ok}`;
}
function agentMessage(r) {
  const msg = chatMessage(r.source === "evidencia" ? "agent data" : "agent", r.answer, turnMeta(r));
  if (r.review?.note) msg.append(el("div", { class: "review-note" }, r.review.note));
  return msg;
}
function renderChatAgents() {
  $("chat-agent-list").replaceChildren(...CHAT_AGENTS.map(([id, label, desc]) => el("label", {},
    el("input", { type: "radio", name: "chat-agent", value: id, checked: id === state.chatAgent }),
    el("strong", {}, label), el("span", { class: "muted small" }, desc))));
  const c = chatCfg();
  $("chat-llm").textContent = c.effective_label ? `Modelo de la conversación: ${c.effective_label} · ${c.effective_model || "sin modelo"}${c.provider || c.model ? "" : " (el mismo de los agentes)"}` : "";
  $("chat-consent-provider").textContent = c.effective_label || "";
  $("chat-consent-box").hidden = !c.off_lan;
}
async function loadChat() {
  renderChatAgents();
  if (!state.run) { $("chat-log").replaceChildren(el("p", { class: "muted" }, "Seleccione un run analizado.")); return; }
  const h = await api(`/api/runs/${state.run}/chat/${state.chatAgent}`);
  $("chat-title").textContent = `Conversación con ${h.label}`;
  $("chat-note").hidden = h.has_agents_output;
  $("chat-note").textContent = "Aún no se ejecutaron los agentes en este run: el agente responderá solo con la evidencia del análisis.";
  downloadLink("dl-chat", `agents/chats/${state.chatAgent}.jsonl`);
  $("dl-chat").hidden = !h.records.length;
  const nodes = [];
  for (const r of h.records) {
    if (r.type === "new_conversation") nodes.push(el("div", { class: "chat-sep" }, `— nueva conversación · ${when(r.ts)} —`));
    else nodes.push(chatMessage("user", r.question, when(r.ts)), agentMessage(r));
  }
  if (!nodes.length) nodes.push(el("p", { class: "muted" }, "Haga una pregunta o use una sugerencia."));
  $("chat-log").replaceChildren(...nodes);
  $("chat-log").scrollTop = $("chat-log").scrollHeight;
  $("chat-suggestions").replaceChildren(...h.suggestions.map((q) => el("button", { type: "button", class: "chip", onclick: () => { $("chat-input").value = q; $("chat-input").focus(); } }, q)));
}
async function sendChat() {
  const message = $("chat-input").value.trim();
  if (!message || state.chatBusy || !state.run) return;
  if (chatCfg().off_lan && !$("chat-consent").checked) { $("chat-consent-box").hidden = false; $("chat-consent").focus(); return; }
  state.chatBusy = true;
  $("chat-send").disabled = true;
  $("chat-input").value = "";
  const log = $("chat-log");
  if (log.querySelector("p.muted")) log.replaceChildren();
  const answer = chatMessage("agent typing", "");
  log.append(chatMessage("user", message), answer);
  log.scrollTop = log.scrollHeight;
  const done = () => { state.chatBusy = false; $("chat-send").disabled = false; answer.classList.remove("typing"); };
  try {
    const { job_id } = await api(`/api/runs/${state.run}/chat`, { method: "POST", json: { agent: state.chatAgent, message, cloud_consent: $("chat-consent").checked } });
    followJob(job_id, (ev) => {
      if (ev.kind === "delta") { answer.firstChild ? answer.firstChild.appendData(ev.message) : answer.append(document.createTextNode(ev.message)); log.scrollTop = log.scrollHeight; }
    }, async (job) => {
      done();
      if (job.status === "failed") { answer.replaceChildren(document.createTextNode(`No se pudo responder: ${(job.error || "").replace(/^\w+Error: /, "")}`)); answer.classList.add("fail"); return; }
      await loadChat();
    });
  } catch (e) { done(); answer.replaceChildren(document.createTextNode(e.message)); }
}
$("chat-agent-list").addEventListener("change", (e) => { if (e.target.name === "chat-agent") { state.chatAgent = e.target.value; loadChat().catch(alertMsg); } });
$("chat-form").addEventListener("submit", (e) => { e.preventDefault(); sendChat(); });
$("chat-input").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); } });
$("chat-new").addEventListener("click", async () => {
  if (!state.run || state.chatBusy) return;
  try { await api(`/api/runs/${state.run}/chat/${state.chatAgent}/new`, { method: "POST" }); await loadChat(); } catch (e) { alertMsg(e); }
});
document.querySelector('[data-tab="chat"]').addEventListener("click", () => loadChat().catch(alertMsg));

$("logout")?.addEventListener("click", async () => { await api("/logout", { method: "POST" }); window.location = "/login"; });

/* ---------------------------------------------------------------- inicio */
(async function init() {
  try {
    const [, , llmState] = await Promise.all([loadConfig(), loadDatasets(), api("/api/llm")]);
    renderLlm(llmState, false);
    await loadTI();
    await loadRuns();
    llmStatus();
  } catch (e) { alertMsg(e); }
})();
