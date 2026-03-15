const els = {
  statusDot: document.getElementById("statusDot"),
  statusText: document.getElementById("statusText"),
  statusSince: document.getElementById("statusSince"),
  packetCount: document.getElementById("packetCount"),
  startBtn: document.getElementById("startBtn"),
  stopBtn: document.getElementById("stopBtn"),
  restartBtn: document.getElementById("restartBtn"),
  clearBtn: document.getElementById("clearBtn"),
  analyzeBtn: document.getElementById("analyzeBtn"),
  refreshBtn: document.getElementById("refreshBtn"),
  rangeSelect: document.getElementById("rangeSelect"),
  queryInput: document.getElementById("queryInput"),
  protocolFilter: document.getElementById("protocolFilter"),
  severityFilter: document.getElementById("severityFilter"),
  alertStatusFilter: document.getElementById("alertStatusFilter"),
  riskScore: document.getElementById("riskScore"),
  riskLevel: document.getElementById("riskLevel"),
  summaryPackets: document.getElementById("summaryPackets"),
  summaryBytes: document.getElementById("summaryBytes"),
  summaryAlerts: document.getElementById("summaryAlerts"),
  summaryHosts: document.getElementById("summaryHosts"),
  summaryDomains: document.getElementById("summaryDomains"),
  statusBreakdown: document.getElementById("statusBreakdown"),
  trafficChart: document.getElementById("trafficChart"),
  alertChart: document.getElementById("alertChart"),
  protocolMix: document.getElementById("protocolMix"),
  topDomains: document.getElementById("topDomains"),
  alertRows: document.getElementById("alertRows"),
  alertDetail: document.getElementById("alertDetail"),
  hostRows: document.getElementById("hostRows"),
  hostDetail: document.getElementById("hostDetail"),
  packetRows: document.getElementById("packetRows"),
  tabButtons: Array.from(document.querySelectorAll("[data-tab]")),
  tabPanels: Array.from(document.querySelectorAll("[data-tab-panel]")),
};

const state = {
  selectedAlertId: null,
  selectedHostIp: null,
  dashboard: null,
  refreshTimer: null,
  activeTab: "overview",
};

function setActiveTab(tabName) {
  state.activeTab = tabName;
  els.tabButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tabName);
  });
  els.tabPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.tabPanel === tabName);
  });
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}

function formatTime(epoch) {
  if (!epoch) return "-";
  return new Date(epoch * 1000).toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getFilters() {
  return new URLSearchParams({
    range: els.rangeSelect.value,
    query: els.queryInput.value.trim(),
    protocol: els.protocolFilter.value,
    severity: els.severityFilter.value,
    alert_status: els.alertStatusFilter.value,
    limit: "20",
  });
}

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    throw new Error(`Request failed: ${res.status}`);
  }
  return res.json();
}

function updateStatus(status) {
  if (status.running) {
    els.statusDot.classList.add("on");
    els.statusText.textContent = "Capturing";
    els.statusSince.textContent = status.started_at
      ? `Started ${formatTime(status.started_at)}`
      : "Capture active";
  } else {
    els.statusDot.classList.remove("on");
    els.statusText.textContent = "Stopped";
    els.statusSince.textContent = "Capture idle";
  }
  els.packetCount.textContent = `${formatNumber(status.packet_count)} total packets`;
}

function renderSummary(data) {
  const summary = data.summary || {};
  const risk = data.risk || {};
  const breakdown = data.status_breakdown || {};

  els.riskScore.textContent = risk.score ?? 0;
  els.riskLevel.textContent = risk.level ?? "Low";
  els.summaryPackets.textContent = formatNumber(summary.packet_count);
  els.summaryBytes.textContent = formatBytes(summary.total_bytes);
  els.summaryAlerts.textContent = formatNumber(summary.alert_count);
  els.summaryHosts.textContent = formatNumber(summary.host_touch_count);
  els.summaryDomains.textContent = `${formatNumber(summary.unique_domains)} domains`;
  els.statusBreakdown.textContent =
    `New ${breakdown.new || 0} | Investigating ${breakdown.investigating || 0} | Resolved ${breakdown.resolved || 0}`;
}

function renderBars(container, items, valueKey, labelFn, formatter) {
  if (!items || items.length === 0) {
    container.innerHTML = `<div class="empty-state">No data in the selected range.</div>`;
    return;
  }
  const maxValue = Math.max(...items.map((item) => item[valueKey] || 0), 1);
  container.innerHTML = items
    .map((item) => {
      const width = Math.max(6, ((item[valueKey] || 0) / maxValue) * 100);
      return `
        <div class="bar-row">
          <div class="bar-label">${labelFn(item)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div>
          <div class="bar-value">${formatter(item[valueKey] || 0)}</div>
        </div>
      `;
    })
    .join("");
}

function renderTrafficChart(items) {
  renderBars(
    els.trafficChart,
    items,
    "packets",
    (item) => new Date(item.bucket_start * 1000).toLocaleTimeString(),
    (value) => formatNumber(value)
  );
}

function renderAlertChart(items) {
  renderBars(
    els.alertChart,
    items,
    "count",
    (item) => new Date(item.bucket_start * 1000).toLocaleTimeString(),
    (value) => formatNumber(value)
  );
}

function renderMiniList(container, rows, labelKey, countKey = "count") {
  if (!rows || rows.length === 0) {
    container.innerHTML = `<div class="empty-state">No data in the selected range.</div>`;
    return;
  }
  const maxValue = Math.max(...rows.map((row) => row[countKey] || 0), 1);
  container.innerHTML = rows
    .map((row) => {
      const width = Math.max(6, ((row[countKey] || 0) / maxValue) * 100);
      return `
        <div class="mini-row">
          <div class="mini-title">${escapeHtml(row[labelKey] || row.value || "-")}</div>
          <div class="mini-track"><div class="mini-fill" style="width:${width}%"></div></div>
          <div class="mini-value">${formatNumber(row[countKey] || 0)}</div>
        </div>
      `;
    })
    .join("");
}

function renderAlerts(alerts) {
  if (!alerts || alerts.length === 0) {
    els.alertRows.innerHTML = `<tr><td colspan="7">No incidents matched the current filters.</td></tr>`;
    els.alertDetail.innerHTML = `<div class="detail-empty">No alert selected.</div>`;
    return;
  }

  els.alertRows.innerHTML = alerts
    .map((alert) => {
      const activeClass = alert.id === state.selectedAlertId ? "active-row" : "";
      return `
        <tr class="${activeClass}" data-alert-id="${alert.id}">
          <td>${escapeHtml(alert.type)}</td>
          <td>${escapeHtml(alert.src_ip || "-")} -> ${escapeHtml(alert.dst_ip || "-")}</td>
          <td><span class="pill severity-${String(alert.severity || "").toLowerCase()}">${escapeHtml(alert.severity || "-")}</span></td>
          <td>${escapeHtml(alert.status || "new")}</td>
          <td>${escapeHtml(alert.owner || "-")}</td>
          <td>${formatNumber(alert.event_count || 1)}</td>
          <td>${formatTime(alert.last_seen || alert.timestamp)}</td>
        </tr>
      `;
    })
    .join("");

  document.querySelectorAll("[data-alert-id]").forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedAlertId = Number(row.dataset.alertId);
      renderAlerts(state.dashboard.alerts || []);
      loadAlertDetail(state.selectedAlertId);
    });
  });

  if (state.selectedAlertId == null) {
    state.selectedAlertId = alerts[0].id;
  }
  loadAlertDetail(state.selectedAlertId);
}

async function loadAlertDetail(alertId) {
  if (!alertId) return;
  const alert = await fetchJson(`/api/alerts/${alertId}`);
  els.alertDetail.innerHTML = `
    <div class="detail-stack">
      <div class="detail-metrics">
        <div><span class="meta-label">Type</span><strong>${escapeHtml(alert.type)}</strong></div>
        <div><span class="meta-label">First Seen</span><strong>${formatTime(alert.first_seen)}</strong></div>
        <div><span class="meta-label">Last Seen</span><strong>${formatTime(alert.last_seen || alert.timestamp)}</strong></div>
        <div><span class="meta-label">Events</span><strong>${formatNumber(alert.event_count || 1)}</strong></div>
      </div>
      <div class="detail-copy">
        <p><strong>Reason:</strong> ${escapeHtml(alert.reason || "-")}</p>
        <p><strong>What:</strong> ${escapeHtml(alert.what || "-")}</p>
        <p><strong>Likely Cause:</strong> ${escapeHtml(alert.possible_causes || "-")}</p>
        <p><strong>Impact:</strong> ${escapeHtml(alert.impact || "-")}</p>
      </div>
      <label><span>Status</span>
        <select id="alertStatusInput">
          ${["new", "acknowledged", "investigating", "resolved", "false_positive"]
            .map((value) => `<option value="${value}" ${value === alert.status ? "selected" : ""}>${value}</option>`)
            .join("")}
        </select>
      </label>
      <label><span>Owner</span><input id="alertOwnerInput" type="text" value="${escapeHtml(alert.owner || "")}" /></label>
      <label><span>Notes</span><textarea id="alertNotesInput" rows="4">${escapeHtml(alert.notes || "")}</textarea></label>
      <label><span>Resolution</span><textarea id="alertResolutionInput" rows="3">${escapeHtml(alert.resolution || "")}</textarea></label>
      <button class="btn primary" id="saveAlertBtn">Save Triage Update</button>
    </div>
  `;

  document.getElementById("saveAlertBtn").addEventListener("click", async () => {
    await fetchJson(`/api/alerts/${alertId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: document.getElementById("alertStatusInput").value,
        owner: document.getElementById("alertOwnerInput").value,
        notes: document.getElementById("alertNotesInput").value,
        resolution: document.getElementById("alertResolutionInput").value,
      }),
    });
    await refreshDashboard();
  });
}

function renderHosts(hosts) {
  if (!hosts || hosts.length === 0) {
    els.hostRows.innerHTML = `<tr><td colspan="7">No hosts found for the current filters.</td></tr>`;
    els.hostDetail.innerHTML = `<div class="detail-empty">No host selected.</div>`;
    return;
  }

  els.hostRows.innerHTML = hosts
    .map((host) => {
      const activeClass = host.ip === state.selectedHostIp ? "active-row" : "";
      const tag = host.is_allowlisted ? "allowlisted" : host.role || "unknown";
      return `
        <tr class="${activeClass}" data-host-ip="${host.ip}">
          <td>${escapeHtml(host.display_name)}<div class="table-sub">${escapeHtml(host.ip)}</div></td>
          <td><span class="pill">${escapeHtml(tag)}</span></td>
          <td>${formatNumber(host.packet_count)}</td>
          <td>${formatNumber(host.peer_count)}</td>
          <td>${escapeHtml(host.top_protocol || "-")}</td>
          <td>${formatNumber(host.alert_count || 0)}</td>
          <td>${formatTime(host.last_seen)}</td>
        </tr>
      `;
    })
    .join("");

  document.querySelectorAll("[data-host-ip]").forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedHostIp = row.dataset.hostIp;
      renderHosts(state.dashboard.hosts || []);
      loadHostDetail(state.selectedHostIp);
    });
  });

  if (!state.selectedHostIp) {
    state.selectedHostIp = hosts[0].ip;
  }
  loadHostDetail(state.selectedHostIp);
}

async function loadHostDetail(ip) {
  if (!ip) return;
  const detail = await fetchJson(`/api/hosts/${encodeURIComponent(ip)}?range=${els.rangeSelect.value}`);
  const profile = detail.profile || {};
  els.hostDetail.innerHTML = `
    <div class="detail-stack">
      <div class="detail-metrics">
        <div><span class="meta-label">Packets</span><strong>${formatNumber(detail.summary.packet_count || 0)}</strong></div>
        <div><span class="meta-label">Peers</span><strong>${formatNumber(detail.summary.peer_count || 0)}</strong></div>
        <div><span class="meta-label">Bytes</span><strong>${formatBytes(detail.summary.total_bytes || 0)}</strong></div>
        <div><span class="meta-label">Last Seen</span><strong>${formatTime(detail.summary.last_seen)}</strong></div>
      </div>
      <label><span>Display Name</span><input id="hostNameInput" type="text" value="${escapeHtml(profile.display_name || ip)}" /></label>
      <label><span>Role</span><input id="hostRoleInput" type="text" value="${escapeHtml(profile.role || "")}" /></label>
      <label><span>Owner</span><input id="hostOwnerInput" type="text" value="${escapeHtml(profile.owner || "")}" /></label>
      <label><span>Notes</span><textarea id="hostNotesInput" rows="3">${escapeHtml(profile.notes || "")}</textarea></label>
      <label class="toggle">
        <input id="hostAllowlistInput" type="checkbox" ${profile.is_allowlisted ? "checked" : ""} />
        <span>Allowlist this host</span>
      </label>
      <button class="btn primary" id="saveHostBtn">Save Host Profile</button>
      <div class="detail-columns">
        <div>
          <h3>Top Peers</h3>
          ${renderList(detail.top_peers)}
        </div>
        <div>
          <h3>Top Domains</h3>
          ${renderList(detail.top_domains)}
        </div>
      </div>
      <div>
        <h3>Recent Alerts</h3>
        ${renderInlineAlerts(detail.recent_alerts)}
      </div>
    </div>
  `;

  document.getElementById("saveHostBtn").addEventListener("click", async () => {
    await fetchJson(`/api/hosts/${encodeURIComponent(ip)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        display_name: document.getElementById("hostNameInput").value,
        role: document.getElementById("hostRoleInput").value,
        owner: document.getElementById("hostOwnerInput").value,
        notes: document.getElementById("hostNotesInput").value,
        is_allowlisted: document.getElementById("hostAllowlistInput").checked,
      }),
    });
    await refreshDashboard();
  });
}

function renderList(items) {
  if (!items || items.length === 0) return `<div class="empty-state">No data.</div>`;
  return items
    .map((item) => `<div class="inline-row"><span>${escapeHtml(item.value)}</span><strong>${formatNumber(item.count)}</strong></div>`)
    .join("");
}

function renderInlineAlerts(alerts) {
  if (!alerts || alerts.length === 0) return `<div class="empty-state">No host-linked alerts in range.</div>`;
  return alerts
    .slice(0, 5)
    .map(
      (alert) => `
        <div class="inline-alert">
          <span>${escapeHtml(alert.type)}</span>
          <span>${escapeHtml(alert.status || "new")}</span>
          <span>${formatTime(alert.last_seen || alert.timestamp)}</span>
        </div>
      `
    )
    .join("");
}

function renderPackets(packets) {
  if (!packets || packets.length === 0) {
    els.packetRows.innerHTML = `<tr><td colspan="8">No packets matched the current filters.</td></tr>`;
    return;
  }
  els.packetRows.innerHTML = packets
    .map(
      (packet) => `
        <tr>
          <td>${formatTime(packet.timestamp)}</td>
          <td>${escapeHtml(packet.domain || "-")}</td>
          <td>${escapeHtml(packet.src_ip || "-")}</td>
          <td>${escapeHtml(packet.dst_ip || "-")}</td>
          <td>${escapeHtml(packet.protocol || "-")}</td>
          <td>${escapeHtml(packet.src_port ?? "-")}</td>
          <td>${escapeHtml(packet.dst_port ?? "-")}</td>
          <td>${formatNumber(packet.size || 0)}</td>
        </tr>
      `
    )
    .join("");
}

async function refreshDashboard() {
  const data = await fetchJson(`/api/dashboard?${getFilters().toString()}`);
  state.dashboard = data;
  updateStatus(data.status || {});
  renderSummary(data);
  renderTrafficChart(data.traffic_timeline || []);
  renderAlertChart(data.alert_timeline || []);
  renderMiniList(els.protocolMix, data.protocol_mix || [], "protocol");
  renderMiniList(els.topDomains, data.top_domains || [], "domain");
  renderAlerts(data.alerts || []);
  renderHosts(data.hosts || []);
  renderPackets(data.packets || []);
}

async function runLiveAnalysis() {
  const data = await fetchJson("/api/analyze", { method: "POST" });
  els.riskScore.textContent = data.risk_score ?? 0;
  els.riskLevel.textContent = `${data.risk_level || "Low"} | ${data.alert_count || 0} live alerts`;
  await refreshDashboard();
}

function scheduleRefresh() {
  clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(() => {
    refreshDashboard().catch(() => {
      els.statusText.textContent = "Disconnected";
    });
  }, 5000);
}

els.startBtn.addEventListener("click", async () => {
  await fetchJson("/api/start", { method: "POST" });
  await refreshDashboard();
});

els.stopBtn.addEventListener("click", async () => {
  await fetchJson("/api/stop", { method: "POST" });
  await refreshDashboard();
});

els.restartBtn.addEventListener("click", async () => {
  await fetchJson("/api/restart", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ clear_history: false }),
  });
  await refreshDashboard();
});

els.clearBtn.addEventListener("click", async () => {
  await fetchJson("/api/history/reset", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ clear_features: true }),
  });
  await refreshDashboard();
});

els.analyzeBtn.addEventListener("click", runLiveAnalysis);
els.refreshBtn.addEventListener("click", refreshDashboard);

els.tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    setActiveTab(button.dataset.tab);
  });
});

[els.rangeSelect, els.protocolFilter, els.severityFilter, els.alertStatusFilter].forEach((el) => {
  el.addEventListener("change", refreshDashboard);
});

let queryTimer = null;
els.queryInput.addEventListener("input", () => {
  clearTimeout(queryTimer);
  queryTimer = setTimeout(() => refreshDashboard(), 350);
});

refreshDashboard().catch(() => {
  els.statusText.textContent = "Disconnected";
});
setActiveTab(state.activeTab);
scheduleRefresh();
