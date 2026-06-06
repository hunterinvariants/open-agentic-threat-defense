const els = {
  loginView: document.querySelector("#login-view"),
  appView: document.querySelector("#app-view"),
  loginForm: document.querySelector("#login-form"),
  loginUsername: document.querySelector("#login-username"),
  loginToken: document.querySelector("#login-token"),
  loginError: document.querySelector("#login-error"),
  loginSubmit: document.querySelector("#login-submit"),
  sessionLabel: document.querySelector("#session-label"),
  version: document.querySelector("#version"),
  loadDemo: document.querySelector("#load-demo"),
  refresh: document.querySelector("#refresh"),
  logout: document.querySelector("#logout"),
  metrics: {
    events: document.querySelector("#metric-events"),
    alerts: document.querySelector("#metric-alerts"),
    assets: document.querySelector("#metric-assets"),
    actions: document.querySelector("#metric-actions"),
    audit: document.querySelector("#metric-audit")
  },
  graph: document.querySelector("#asset-graph"),
  assetsBody: document.querySelector("#assets-body"),
  alertsList: document.querySelector("#alerts-list"),
  eventsList: document.querySelector("#events-list"),
  actionsList: document.querySelector("#actions-list"),
  rulesList: document.querySelector("#rules-list")
};

const emptyTemplate = document.querySelector("#empty-template");
const state = {
  session: null,
  pollHandle: null
};

async function api(path, options = {}) {
  const { useToken = true, ...fetchOptions } = options;
  const headers = {
    "Content-Type": "application/json",
    ...(fetchOptions.headers || {})
  };
  const token = useToken ? sessionStorage.getItem("oatd_api_token") : "";
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(path, {
    credentials: "same-origin",
    ...fetchOptions,
    headers
  });
  const bodyText = await response.text();
  const payload = bodyText ? tryParseJSON(bodyText) : null;
  if (!response.ok) {
    const error = new Error((payload && payload.error) || `${response.status} ${response.statusText}`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function tryParseJSON(value) {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function isLoggedIn() {
  return Boolean(state.session && state.session.authenticated);
}

function setView(session) {
  state.session = session;
  const loggedIn = isLoggedIn();
  document.body.classList.toggle("logged-out", !loggedIn);
  els.loginView.hidden = loggedIn;
  els.appView.hidden = !loggedIn;
  if (loggedIn) {
    const principal = session.principal || {};
    const mode = session.mode || "session";
    const roles = Array.isArray(principal.roles) ? principal.roles.join(", ") : "";
    els.sessionLabel.textContent = roles ? `${principal.name} - ${mode} - ${roles}` : `${principal.name} - ${mode}`;
  } else {
    els.sessionLabel.textContent = "";
  }
}

function showLogin(message = "") {
  stopPolling();
  setView({ authenticated: false });
  els.loginError.textContent = message;
  els.loginSubmit.disabled = false;
  els.loginForm.reset();
  els.loginUsername.focus();
}

function showApp(session) {
  els.loginError.textContent = "";
  setView(session);
  startPolling();
}

function startPolling() {
  stopPolling();
  state.pollHandle = window.setInterval(() => {
    refresh().catch(handleApiFailure);
  }, 8000);
}

function stopPolling() {
  if (state.pollHandle !== null) {
    window.clearInterval(state.pollHandle);
    state.pollHandle = null;
  }
}

function handleApiFailure(error) {
  if (error && error.status === 401) {
    sessionStorage.removeItem("oatd_api_token");
    showLogin("Session expired.");
    return;
  }
  console.error(error);
}

async function loadSession() {
  const session = await api("/api/session");
  if (session && session.authenticated) {
    showApp(session);
    return true;
  }
  showLogin();
  return false;
}

async function refresh() {
  if (!isLoggedIn()) {
    return;
  }

  const [status, alerts, assets, events, actions, rules] = await Promise.all([
    api("/api/status"),
    api("/api/alerts"),
    api("/api/assets"),
    api("/api/events"),
    api("/api/responses"),
    api("/api/policies")
  ]);

  renderStatus(status);
  renderGraph(assets, alerts);
  renderAssets(assets);
  renderAlerts(alerts);
  renderEvents(events);
  renderActions(actions);
  renderRules(rules);
}

function renderStatus(status) {
  els.metrics.events.textContent = status.event_count;
  els.metrics.alerts.textContent = status.alert_count;
  els.metrics.assets.textContent = status.asset_count;
  els.metrics.actions.textContent = status.action_count;
  els.metrics.audit.textContent = status.audit_count;
  els.version.textContent = status.version;
}

function renderAssets(assets) {
  els.assetsBody.innerHTML = "";
  if (!assets.length) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="4"><div class="empty">No assets loaded.</div></td>`;
    els.assetsBody.append(row);
    return;
  }

  assets.forEach((asset) => {
    const row = document.createElement("tr");
    const risk = Math.min(asset.risk_score || 0, 100);
    row.innerHTML = `
      <td><strong>${escapeHtml(asset.hostname || asset.id)}</strong><div class="item-meta">${escapeHtml(asset.id)}</div></td>
      <td>${escapeHtml((asset.ips || []).join(", ") || "-")}</td>
      <td>${escapeHtml((asset.agent_surface || []).join(", ") || "-")}</td>
      <td>
        <div class="risk-bar" aria-label="Risk ${risk}"><span style="width:${risk}%"></span></div>
        <div class="item-meta">${risk}</div>
      </td>
    `;
    els.assetsBody.append(row);
  });
}

function renderAlerts(alerts) {
  els.alertsList.innerHTML = "";
  if (!alerts.length) {
    els.alertsList.append(emptyNode());
    return;
  }

  alerts.forEach((alert) => {
    const node = document.createElement("article");
    node.className = `alert-item ${alert.severity}`;
    node.innerHTML = `
      <div class="item-top">
        <div class="item-title">${escapeHtml(alert.title)}</div>
        <span class="badge severity-${alert.severity}">${escapeHtml(alert.severity)}</span>
      </div>
      <div class="item-meta">${escapeHtml(alert.asset_id || "unknown asset")} - ${escapeHtml(alert.rule_id)}</div>
      <p class="item-body">${escapeHtml(alert.description)}</p>
      <div class="kv">${renderEvidence(alert.evidence)}</div>
      <div class="item-top action-row">
        <span class="item-meta">${formatTime(alert.created_at)}</span>
        <button class="small" data-respond="${escapeHtml(alert.id)}">Plan Response</button>
      </div>
    `;
    els.alertsList.append(node);
  });
}

function renderEvents(events) {
  els.eventsList.innerHTML = "";
  if (!events.length) {
    els.eventsList.append(emptyNode());
    return;
  }

  events.slice(0, 80).forEach((event) => {
    const node = document.createElement("article");
    node.className = "event-item";
    node.innerHTML = `
      <div class="item-top">
        <div class="item-title">${escapeHtml(event.kind)}</div>
        <span class="chip">${escapeHtml(event.asset_id || "no asset")}</span>
      </div>
      <div class="item-meta">${formatTime(event.timestamp)} - ${escapeHtml(event.hostname || event.source_ip || "-")}</div>
      <p class="item-body">${escapeHtml(event.signal || event.command || event.destination || "-")}</p>
      <div class="kv">${(event.labels || []).map((label) => `<span class="chip">${escapeHtml(label)}</span>`).join("")}</div>
    `;
    els.eventsList.append(node);
  });
}

function renderActions(actions) {
  els.actionsList.innerHTML = "";
  if (!actions.length) {
    els.actionsList.append(emptyNode());
    return;
  }

  actions.forEach((action) => {
    const node = document.createElement("article");
    node.className = "action-item";
    node.innerHTML = `
      <div class="item-top">
        <div class="item-title">${escapeHtml(action.type)}</div>
        <span class="chip">${escapeHtml(action.approval_status || action.mode)}</span>
      </div>
      <div class="item-meta">${escapeHtml(action.asset_id || "unknown asset")} - ${escapeHtml(action.target || "-")}</div>
      <p class="item-body">${escapeHtml(action.reason || "")}</p>
      ${action.approval_status === "required" ? `<div class="item-top action-row"><span class="item-meta">approval required</span><button class="small" data-approve="${escapeHtml(action.id)}">Approve</button></div>` : ""}
    `;
    els.actionsList.append(node);
  });
}

function renderRules(rules) {
  els.rulesList.innerHTML = "";
  if (!rules.length) {
    els.rulesList.append(emptyNode());
    return;
  }

  rules.forEach((rule) => {
    const node = document.createElement("article");
    node.className = "rule-item";
    node.innerHTML = `
      <div class="item-top">
        <div class="item-title">${escapeHtml(rule.name)}</div>
        <span class="badge severity-${rule.severity}">${escapeHtml(rule.severity)}</span>
      </div>
      <div class="item-meta">${escapeHtml(rule.id)}</div>
      <p class="item-body">${escapeHtml(rule.description)}</p>
    `;
    els.rulesList.append(node);
  });
}

function renderGraph(assets, alerts) {
  const width = 760;
  const height = 260;
  const safeAssets = assets.length ? assets : [{ id: "empty", hostname: "No assets", risk_score: 0 }];
  const maxRisk = Math.max(1, ...safeAssets.map((asset) => asset.risk_score || 0));
  const alertCounts = alerts.reduce((acc, alert) => {
    acc[alert.asset_id] = (acc[alert.asset_id] || 0) + 1;
    return acc;
  }, {});

  const nodes = safeAssets.slice(0, 8).map((asset, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(safeAssets.length, 1) - Math.PI / 2;
    const radius = 78 + Math.min(42, ((asset.risk_score || 0) / maxRisk) * 42);
    const cx = width / 2 + Math.cos(angle) * 230;
    const cy = height / 2 + Math.sin(angle) * radius;
    const risk = asset.risk_score || 0;
    const fill = risk >= 80 ? "#b42318" : risk >= 50 ? "#b45309" : risk > 0 ? "#0f766e" : "#8a948c";
    return { asset, cx, cy, fill, alerts: alertCounts[asset.id] || 0 };
  });

  const lines = nodes
    .filter((node) => node.asset.id !== "empty")
    .map((node) => `<line x1="${width / 2}" y1="${height / 2}" x2="${node.cx}" y2="${node.cy}" stroke="#d9ded6" stroke-width="2" />`)
    .join("");

  const circles = nodes
    .map((node) => {
      const name = escapeHtml(node.asset.hostname || node.asset.id);
      const risk = Math.min(99, node.asset.risk_score || 0);
      return `
      <g>
        <circle cx="${node.cx}" cy="${node.cy}" r="${28 + Math.min(18, risk / 6)}" fill="${node.fill}" opacity="0.95"></circle>
        <text x="${node.cx}" y="${node.cy + 4}" text-anchor="middle" fill="#fff" font-size="13" font-weight="800">${risk}</text>
        <text x="${node.cx}" y="${node.cy + 53}" text-anchor="middle" fill="#17211c" font-size="12" font-weight="700">${name}</text>
        <text x="${node.cx}" y="${node.cy + 68}" text-anchor="middle" fill="#647067" font-size="11">${node.alerts} alerts</text>
      </g>
    `;
    })
    .join("");

  els.graph.innerHTML = `
    <rect x="0" y="0" width="${width}" height="${height}" fill="#fbfcfa"></rect>
    <circle cx="${width / 2}" cy="${height / 2}" r="42" fill="#17211c"></circle>
    <text x="${width / 2}" y="${height / 2 - 2}" text-anchor="middle" fill="#fff" font-size="12" font-weight="800">OATD</text>
    <text x="${width / 2}" y="${height / 2 + 15}" text-anchor="middle" fill="#d9ded6" font-size="10">control</text>
    ${lines}
    ${circles}
  `;
}

function renderEvidence(evidence = {}) {
  return Object.entries(evidence)
    .slice(0, 5)
    .map(([key, value]) => `<span class="chip">${escapeHtml(key)}: ${escapeHtml(value || "-")}</span>`)
    .join("");
}

function emptyNode() {
  return emptyTemplate.content.firstElementChild.cloneNode(true);
}

function formatTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function login(username, token) {
  const session = await api("/api/session", {
    method: "POST",
    useToken: false,
    body: JSON.stringify({ username, token })
  });
  sessionStorage.removeItem("oatd_api_token");
  showApp(session);
  await refresh();
}

async function logout() {
  try {
    await api("/api/session", {
      method: "DELETE",
      useToken: false
    });
  } catch (error) {
    handleApiFailure(error);
  }
  sessionStorage.removeItem("oatd_api_token");
  showLogin();
}

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  els.loginSubmit.disabled = true;
  els.loginError.textContent = "";
  try {
    await login(els.loginUsername.value, els.loginToken.value);
  } catch (error) {
    if (error && error.status === 401) {
      els.loginError.textContent = "Invalid credentials.";
      return;
    }
    handleApiFailure(error);
    els.loginError.textContent = "Login failed.";
  } finally {
    els.loginSubmit.disabled = false;
  }
});

els.logout.addEventListener("click", () => {
  logout().catch(handleApiFailure);
});

els.loadDemo.addEventListener("click", async () => {
  els.loadDemo.disabled = true;
  try {
    await api("/api/demo", { method: "POST", body: "{}" });
    await refresh();
  } catch (error) {
    handleApiFailure(error);
  } finally {
    els.loadDemo.disabled = false;
  }
});

els.refresh.addEventListener("click", () => {
  refresh().catch(handleApiFailure);
});

els.alertsList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-respond]");
  if (!button) return;
  button.disabled = true;
  try {
    await api("/api/responses", {
      method: "POST",
      body: JSON.stringify({ alert_id: button.dataset.respond })
    });
    await refresh();
  } catch (error) {
    handleApiFailure(error);
  } finally {
    button.disabled = false;
  }
});

els.actionsList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-approve]");
  if (!button) return;
  button.disabled = true;
  try {
    await api("/api/responses/approve", {
      method: "POST",
      body: JSON.stringify({ action_id: button.dataset.approve, approved_by: "dashboard" })
    });
    await refresh();
  } catch (error) {
    handleApiFailure(error);
  } finally {
    button.disabled = false;
  }
});

els.loginUsername.addEventListener("input", () => {
  els.loginError.textContent = "";
});

els.loginToken.addEventListener("input", () => {
  els.loginError.textContent = "";
});

loadSession().then((loggedIn) => {
  if (loggedIn) {
    refresh().catch(handleApiFailure);
  }
}).catch(handleApiFailure);
