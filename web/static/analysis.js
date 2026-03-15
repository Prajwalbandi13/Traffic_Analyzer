const reportEls = {
  reportRange: document.getElementById("reportRange"),
  loadReportBtn: document.getElementById("loadReportBtn"),
  copyReportBtn: document.getElementById("copyReportBtn"),
  reportAlerts: document.getElementById("reportAlerts"),
  reportGenerated: document.getElementById("reportGenerated"),
  reportPackets: document.getElementById("reportPackets"),
  reportBytes: document.getElementById("reportBytes"),
  reportHosts: document.getElementById("reportHosts"),
  reportDomains: document.getElementById("reportDomains"),
  reportWorkflow: document.getElementById("reportWorkflow"),
  reportWorkflowBreakdown: document.getElementById("reportWorkflowBreakdown"),
  reportNarrative: document.getElementById("reportNarrative"),
  reportTrafficChart: document.getElementById("reportTrafficChart"),
  reportProtocolMix: document.getElementById("reportProtocolMix"),
  reportAlertRows: document.getElementById("reportAlertRows"),
  reportHostRows: document.getElementById("reportHostRows"),
};

let lastNarrative = "";

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

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

function renderBars(container, items, valueKey, labelFn) {
  if (!items || items.length === 0) {
    container.innerHTML = `<div class="empty-state">No report data for this range.</div>`;
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
          <div class="bar-value">${formatNumber(item[valueKey] || 0)}</div>
        </div>
      `;
    })
    .join("");
}

function renderMiniList(container, rows, labelKey) {
  if (!rows || rows.length === 0) {
    container.innerHTML = `<div class="empty-state">No data.</div>`;
    return;
  }
  const maxValue = Math.max(...rows.map((row) => row.count || 0), 1);
  container.innerHTML = rows
    .map((row) => {
      const width = Math.max(6, ((row.count || 0) / maxValue) * 100);
      return `
        <div class="mini-row">
          <div class="mini-title">${escapeHtml(row[labelKey] || row.value || "-")}</div>
          <div class="mini-track"><div class="mini-fill" style="width:${width}%"></div></div>
          <div class="mini-value">${formatNumber(row.count || 0)}</div>
        </div>
      `;
    })
    .join("");
}

function renderNarrative(report) {
  const summary = report.summary || {};
  const topAlert = (report.top_alerts || [])[0];
  const topHost = (report.top_hosts || [])[0];
  const status = report.status_breakdown || {};

  lastNarrative = [
    `Report window: ${Number(report.range_seconds || 0) / 3600} hours.`,
    `Observed ${formatNumber(summary.packet_count)} packets totaling ${formatBytes(summary.total_bytes)}.`,
    `Alert workload included ${formatNumber(summary.alert_count)} grouped incidents.`,
    `Workflow state: ${status.new || 0} new, ${status.investigating || 0} investigating, ${status.resolved || 0} resolved.`,
    topAlert
      ? `Highest priority recent incident: ${topAlert.type} affecting ${topAlert.src_ip || "-"} -> ${topAlert.dst_ip || "-"} with ${topAlert.event_count || 1} events.`
      : "No alerts were recorded in the selected period.",
    topHost
      ? `Most active host: ${topHost.display_name || topHost.ip} with ${formatNumber(topHost.packet_count)} packets and ${formatNumber(topHost.alert_count || 0)} linked alerts.`
      : "No host stood out during the selected period.",
  ].join(" ");

  reportEls.reportNarrative.textContent = lastNarrative;
}

function renderReport(report) {
  const summary = report.summary || {};
  const status = report.status_breakdown || {};

  reportEls.reportAlerts.textContent = formatNumber(summary.alert_count);
  reportEls.reportGenerated.textContent = `Generated ${formatTime(report.generated_at)}`;
  reportEls.reportPackets.textContent = formatNumber(summary.packet_count);
  reportEls.reportBytes.textContent = formatBytes(summary.total_bytes);
  reportEls.reportHosts.textContent = formatNumber(summary.host_touch_count);
  reportEls.reportDomains.textContent = `${formatNumber(summary.unique_domains)} domains`;
  reportEls.reportWorkflow.textContent = formatNumber(
    (status.new || 0) + (status.acknowledged || 0) + (status.investigating || 0)
  );
  reportEls.reportWorkflowBreakdown.textContent =
    `New ${status.new || 0} | Investigating ${status.investigating || 0} | Resolved ${status.resolved || 0}`;

  renderNarrative(report);
  renderBars(
    reportEls.reportTrafficChart,
    report.traffic_timeline || [],
    "packets",
    (item) => new Date(item.bucket_start * 1000).toLocaleString()
  );
  renderMiniList(reportEls.reportProtocolMix, report.protocol_mix || [], "protocol");

  const alerts = report.top_alerts || [];
  reportEls.reportAlertRows.innerHTML = alerts.length
    ? alerts
        .map(
          (alert) => `
            <tr>
              <td>${escapeHtml(alert.type)}</td>
              <td>${escapeHtml(alert.status || "new")}</td>
              <td>${escapeHtml(alert.severity || "-")}</td>
              <td>${formatNumber(alert.event_count || 1)}</td>
              <td>${escapeHtml(alert.owner || "-")}</td>
              <td>${formatTime(alert.last_seen || alert.timestamp)}</td>
            </tr>
          `
        )
        .join("")
    : `<tr><td colspan="6">No alerts in this report window.</td></tr>`;

  const hosts = report.top_hosts || [];
  reportEls.reportHostRows.innerHTML = hosts.length
    ? hosts
        .map(
          (host) => `
            <tr>
              <td>${escapeHtml(host.display_name || host.ip)}<div class="table-sub">${escapeHtml(host.ip)}</div></td>
              <td>${escapeHtml(host.role || "unknown")}</td>
              <td>${formatNumber(host.packet_count)}</td>
              <td>${formatNumber(host.alert_count || 0)}</td>
              <td>${escapeHtml(host.top_domain || "-")}</td>
            </tr>
          `
        )
        .join("")
    : `<tr><td colspan="5">No host activity in this report window.</td></tr>`;
}

async function loadReport() {
  const range = reportEls.reportRange.value;
  const report = await fetchJson(`/api/report/summary?range=${range}`);
  renderReport(report);
}

reportEls.loadReportBtn.addEventListener("click", loadReport);
reportEls.reportRange.addEventListener("change", loadReport);
reportEls.copyReportBtn.addEventListener("click", async () => {
  if (!lastNarrative) return;
  await navigator.clipboard.writeText(lastNarrative);
});

loadReport();
