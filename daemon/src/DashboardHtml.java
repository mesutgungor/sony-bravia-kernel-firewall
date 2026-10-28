public class DashboardHtml {
    public static final String HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sony Bravia — Kernel Egress Firewall</title>
<style>
  :root {
    --bg: #0b0f19;
    --panel: #111827;
    --panel-alt: #1e293b;
    --border: #334155;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --green: #22c55e;
    --red: #ef4444;
    --amber: #f59e0b;
    --purple: #a855f7;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    background: var(--bg);
    color: var(--text);
    line-height: 1.45;
    padding: 18px;
  }
  header {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 16px;
    gap: 12px;
  }
  .title-group h1 {
    font-size: 20px;
    color: var(--accent);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .title-group p {
    font-size: 12px;
    color: var(--muted);
    margin-top: 4px;
  }
  .status-pills {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
  }
  .pill {
    padding: 6px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid var(--border);
    background: var(--panel-alt);
  }
  .pill.ok { border-color: var(--green); color: var(--green); background: rgba(34,197,94,0.1); }
  .pill.err { border-color: var(--red); color: var(--red); background: rgba(239,68,68,0.1); }
  .pill.warn { border-color: var(--amber); color: var(--amber); background: rgba(245,158,11,0.1); }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
  }
  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
  }
  .stat-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card .value { font-size: 24px; font-weight: 700; margin-top: 4px; }

  .alerts-box {
    background: rgba(245, 158, 11, 0.08);
    border: 1px solid var(--amber);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 16px;
  }
  .alerts-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
  }
  .alerts-header h3 { font-size: 14px; color: var(--amber); }
  .alert-item {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    padding: 8px 10px;
    background: rgba(15, 23, 42, 0.75);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 6px;
    gap: 8px;
    font-size: 12px;
  }

  .tabs {
    display: flex;
    gap: 8px;
    margin-bottom: 14px;
    flex-wrap: wrap;
  }
  .tab-btn {
    background: var(--panel);
    color: var(--muted);
    border: 1px solid var(--border);
    padding: 9px 16px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
  }
  .tab-btn.active {
    background: var(--accent);
    color: #0f172a;
    border-color: var(--accent);
  }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 16px;
  }
  .card-header {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
  }
  .card-header h2 { font-size: 15px; color: var(--accent); }
  input[type="text"] {
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 7px 12px;
    border-radius: 6px;
    font-size: 13px;
    min-width: 240px;
  }
  .btn {
    padding: 5px 10px;
    border-radius: 5px;
    border: 1px solid var(--border);
    background: var(--panel-alt);
    color: var(--text);
    cursor: pointer;
    font-size: 11px;
    font-weight: 600;
  }
  .btn:hover { opacity: 0.88; }
  .btn-red { background: rgba(239,68,68,0.18); border-color: var(--red); color: #fca5a5; }
  .btn-green { background: rgba(34,197,94,0.18); border-color: var(--green); color: #86efac; }
  .btn-blue { background: rgba(56,189,248,0.18); border-color: var(--accent); color: var(--accent); }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  th, td {
    text-align: left;
    padding: 9px 10px;
    border-bottom: 1px solid rgba(51,65,85,0.6);
    vertical-align: middle;
  }
  th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }
  tr:hover { background: rgba(30,41,59,0.45); }
  .badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
  }
  .badge-allow { background: rgba(34,197,94,0.15); color: var(--green); border: 1px solid var(--green); }
  .badge-block { background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid var(--red); }
  .badge-tun { background: rgba(168,85,247,0.15); color: var(--purple); border: 1px solid var(--purple); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .rule-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  .rule-chip {
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--panel-alt);
    border: 1px solid var(--border);
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 12px;
  }
</style>
</head>
<body>

<header>
  <div class="title-group">
    <h1>🛡️ Sony Bravia — Hybrid Kernel Egress Application Firewall</h1>
    <p>Linux 5.15 Kernel eBPF (<code>BpfNetMaps</code> Chain 2) + Kernel <code>/dev/tun</code> Packet/DNS/SNI Filter</p>
  </div>
  <div class="status-pills">
    <span id="ebpfStatusPill" class="pill ok">Kernel eBPF: ACTIVE</span>
    <span id="tunStatusPill" class="pill ok">/dev/tun VPN: ACTIVE</span>
    <button class="btn btn-blue" onclick="refreshState()">↻ Refresh</button>
  </div>
</header>

<div class="stats-grid">
  <div class="stat-card">
    <div class="label">Apps Blocked (Kernel eBPF)</div>
    <div class="value" id="statBlockedApps" style="color:var(--red)">0</div>
  </div>
  <div class="stat-card">
    <div class="label">Domains Blocked (/dev/tun)</div>
    <div class="value" id="statBlockedDomains" style="color:var(--purple)">0</div>
  </div>
  <div class="stat-card">
    <div class="label">IPs Blackholed (/dev/tun)</div>
    <div class="value" id="statBlockedIps" style="color:var(--amber)">0</div>
  </div>
  <div class="stat-card">
    <div class="label">Active Egress Sockets</div>
    <div class="value" id="statActiveSockets" style="color:var(--accent)">0</div>
  </div>
  <div class="stat-card">
    <div class="label">Blocked Attempts</div>
    <div class="value" id="statTotalBlocked" style="color:var(--red)">0</div>
  </div>
  <div class="stat-card">
    <div class="label">Total Egress Events</div>
    <div class="value" id="statTotalEvents" style="color:var(--green)">0</div>
  </div>
</div>

<div class="alerts-box" id="alertsBox" style="display:none;">
  <div class="alerts-header">
    <h3>🔔 Live Egress Connection Alerts (<span id="alertCount">0</span>)</h3>
    <button class="btn" onclick="apiCall({action:'clear_alerts'})">Dismiss All</button>
  </div>
  <div id="alertsList"></div>
</div>

<div class="tabs">
  <button class="tab-btn active" onclick="switchTab('events', this)">Live Egress Stream</button>
  <button class="tab-btn" onclick="switchTab('sockets', this)">Active Kernel Sockets (/proc/net)</button>
  <button class="tab-btn" onclick="switchTab('apps', this)">App Firewall (Kernel eBPF)</button>
  <button class="tab-btn" onclick="switchTab('domains', this)">Domain & IP Rules (/dev/tun)</button>
  <button class="tab-btn" onclick="switchTab('dns', this)">Live DNS Log</button>
</div>

<!-- TAB 1: LIVE EGRESS STREAM -->
<div id="tab-events" class="tab-panel active">
  <div class="card">
    <div class="card-header">
      <h2>Live Egress Connections & Blocked Attempts</h2>
      <input type="text" id="eventFilter" placeholder="Filter by app, UID, domain, IP..." oninput="renderState()">
    </div>
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Verdict</th>
          <th>App / Package</th>
          <th>UID</th>
          <th>Proto</th>
          <th>Domain / TLS SNI</th>
          <th>Destination IP:Port</th>
          <th>Quick Actions</th>
        </tr>
      </thead>
      <tbody id="eventsTableBody"></tbody>
    </table>
  </div>
</div>

<!-- TAB 2: ACTIVE KERNEL SOCKETS -->
<div id="tab-sockets" class="tab-panel">
  <div class="card">
    <div class="card-header">
      <h2>Active Outbound Kernel Sockets (<code>/proc/net/tcp*</code> & <code>/proc/net/udp*</code>)</h2>
      <input type="text" id="socketFilter" placeholder="Filter sockets..." oninput="renderState()">
    </div>
    <table>
      <thead>
        <tr>
          <th>State</th>
          <th>Kernel eBPF Status</th>
          <th>App / Package</th>
          <th>UID</th>
          <th>Proto</th>
          <th>Resolved Domain</th>
          <th>Local Address</th>
          <th>Remote Address</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="socketsTableBody"></tbody>
    </table>
  </div>
</div>

<!-- TAB 3: KERNEL eBPF APP FIREWALL -->
<div id="tab-apps" class="tab-panel">
  <div class="card">
    <div class="card-header">
      <h2>Per-App Kernel eBPF Firewall (<code>BpfNetMaps</code> STANDBY Chain 2)</h2>
      <input type="text" id="appFilter" placeholder="Search 289 UIDs / 325 packages..." oninput="renderState()">
    </div>
    <table>
      <thead>
        <tr>
          <th>eBPF Status</th>
          <th>UID</th>
          <th>Package(s)</th>
          <th>Type</th>
          <th>Active Sockets</th>
          <th>Events Seen</th>
          <th>Kernel eBPF Action</th>
        </tr>
      </thead>
      <tbody id="appsTableBody"></tbody>
    </table>
  </div>
</div>

<!-- TAB 4: DOMAIN & IP RULES -->
<div id="tab-domains" class="tab-panel">
  <div class="card">
    <div class="card-header">
      <h2>Blocked Domains (<code>/dev/tun</code> DNS Sinkhole + TLS SNI Trap)</h2>
      <div style="display:flex;gap:8px;">
        <input type="text" id="newDomainInput" placeholder="e.g. ads.example.com or *.tracker.net">
        <button class="btn btn-red" onclick="addDomainRule()">+ Block Domain</button>
      </div>
    </div>
    <div id="domainRulesList" class="rule-list"></div>
  </div>

  <div class="card">
    <div class="card-header">
      <h2>Blackholed IPv4 Addresses (<code>/dev/tun</code> <code>/32</code> Kernel Routes)</h2>
      <div style="display:flex;gap:8px;">
        <input type="text" id="newIpInput" placeholder="e.g. 52.210.10.20">
        <button class="btn btn-red" onclick="addIpRule()">+ Block IP</button>
      </div>
    </div>
    <div id="ipRulesList" class="rule-list"></div>
  </div>
</div>

<!-- TAB 5: LIVE DNS LOG -->
<div id="tab-dns" class="tab-panel">
  <div class="card">
    <div class="card-header">
      <h2>Live <code>/dev/tun</code> DNS Queries & Resolutions</h2>
    </div>
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Verdict</th>
          <th>Query Domain</th>
          <th>Resolved / Sinkhole IPs</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="dnsTableBody"></tbody>
    </table>
  </div>
</div>

<script>
let lastState = null;

function switchTab(name, btn) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}

async function apiCall(params) {
  const body = new URLSearchParams(params).toString();
  await fetch('/api/action', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body
  });
  await refreshState();
}

function addDomainRule() {
  const v = document.getElementById('newDomainInput').value.trim();
  if (!v) return;
  document.getElementById('newDomainInput').value = '';
  apiCall({action: 'block_domain', domain: v});
}

function addIpRule() {
  const v = document.getElementById('newIpInput').value.trim();
  if (!v) return;
  document.getElementById('newIpInput').value = '';
  apiCall({action: 'block_ip', ip: v});
}

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function refreshState() {
  try {
    const r = await fetch('/api/state');
    lastState = await r.json();
    renderState();
  } catch (e) {
    console.error(e);
  }
}

function renderState() {
  if (!lastState) return;
  const s = lastState;

  document.getElementById('statBlockedApps').textContent = s.blockedUids.length;
  document.getElementById('statBlockedDomains').textContent = s.blockedDomains.length;
  document.getElementById('statBlockedIps').textContent = s.blockedIps.length;
  document.getElementById('statActiveSockets').textContent = s.activeSockets.length;
  document.getElementById('statTotalBlocked').textContent = s.totalBlocked;
  document.getElementById('statTotalEvents').textContent = s.totalEvents;

  const ebpfPill = document.getElementById('ebpfStatusPill');
  ebpfPill.textContent = 'Kernel eBPF: ' + (s.ebpfEnabled ? 'ACTIVE (Chain 2)' : 'DISABLED');
  ebpfPill.className = 'pill ' + (s.ebpfEnabled ? 'ok' : 'err');

  const tunPill = document.getElementById('tunStatusPill');
  tunPill.textContent = '/dev/tun VPN: ' + s.tunStatus;
  tunPill.className = 'pill ' + (s.tunStatus.startsWith('ACTIVE') ? 'ok' : 'warn');

  // Render Alerts
  const alertsBox = document.getElementById('alertsBox');
  const alertsList = document.getElementById('alertsList');
  document.getElementById('alertCount').textContent = s.alerts.length;
  if (s.alerts.length === 0) {
    alertsBox.style.display = 'none';
  } else {
    alertsBox.style.display = 'block';
    alertsList.innerHTML = s.alerts.map(a => `
      <div class="alert-item">
        <div>
          <span class="badge ${a.blocked ? 'badge-block' : 'badge-allow'}">${esc(a.type)}</span>
          <strong style="margin-left:6px;">${esc(a.pkg)}</strong> <span class="mono">(uid=${a.uid})</span>
          &rarr; <strong style="color:var(--accent)">${esc(a.domain !== '-' ? a.domain : a.dstIp)}</strong>
          <span class="mono">(${esc(a.proto)} ${esc(a.dstIp)}:${a.dstPort})</span>
          <span style="color:var(--muted);margin-left:6px;">${esc(a.time)}</span>
        </div>
        <div style="display:flex;gap:6px;">
          ${a.uid >= 10000 ? `<button class="btn btn-red" onclick="apiCall({action:'block_uid',uid:${a.uid}})">Block App (eBPF)</button>` : ''}
          ${a.domain && a.domain !== '-' ? `<button class="btn btn-red" onclick="apiCall({action:'block_domain',domain:'${esc(a.domain)}'})">Block Domain</button>` : ''}
          ${a.dstIp && !a.dstIp.startsWith('10.254.') ? `<button class="btn btn-red" onclick="apiCall({action:'block_ip',ip:'${esc(a.dstIp)}'})">Block IP</button>` : ''}
          <button class="btn" onclick="apiCall({action:'dismiss_alert',id:${a.id}})">Dismiss</button>
        </div>
      </div>
    `).join('');
  }

  // Render Events
  const ef = (document.getElementById('eventFilter').value || '').toLowerCase();
  const evBody = document.getElementById('eventsTableBody');
  evBody.innerHTML = s.events.filter(e => {
    if (!ef) return true;
    return (e.pkg + ' ' + e.uid + ' ' + e.domain + ' ' + e.dstIp + ' ' + e.verdict).toLowerCase().includes(ef);
  }).map(e => {
    const isBlk = e.verdict.startsWith('BLOCKED');
    const badgeCls = isBlk ? (e.verdict.includes('TUN') ? 'badge-tun' : 'badge-block') : 'badge-allow';
    const uidBlocked = s.blockedUids.includes(e.uid);
    return `
      <tr>
        <td class="mono">${esc(e.time)}</td>
        <td><span class="badge ${badgeCls}">${esc(e.verdict)}</span></td>
        <td><strong>${esc(e.pkg)}</strong></td>
        <td class="mono">${e.uid}</td>
        <td class="mono">${esc(e.proto)}</td>
        <td style="color:var(--accent);font-weight:600;">${esc(e.domain)}</td>
        <td class="mono">${esc(e.dstIp)}:${e.dstPort}</td>
        <td style="display:flex;gap:5px;flex-wrap:wrap;">
          ${e.uid >= 10000 ? (uidBlocked
            ? `<button class="btn btn-green" onclick="apiCall({action:'allow_uid',uid:${e.uid}})">Unblock App</button>`
            : `<button class="btn btn-red" onclick="apiCall({action:'block_uid',uid:${e.uid}})">Block App (eBPF)</button>`) : ''}
          ${e.domain && e.domain !== '-' ? `<button class="btn btn-red" onclick="apiCall({action:'block_domain',domain:'${esc(e.domain)}'})">Block Domain</button>` : ''}
          ${e.dstIp && !e.dstIp.startsWith('10.254.') && e.dstIp !== '-' ? `<button class="btn btn-red" onclick="apiCall({action:'block_ip',ip:'${esc(e.dstIp)}'})">Block IP</button>` : ''}
        </td>
      </tr>
    `;
  }).join('');

  // Render Active Sockets
  const sf = (document.getElementById('socketFilter').value || '').toLowerCase();
  const sockBody = document.getElementById('socketsTableBody');
  sockBody.innerHTML = s.activeSockets.filter(k => {
    if (!sf) return true;
    return (k.pkg + ' ' + k.uid + ' ' + k.domain + ' ' + k.remoteIp).toLowerCase().includes(sf);
  }).map(k => {
    const uidBlocked = s.blockedUids.includes(k.uid);
    return `
      <tr>
        <td class="mono">${esc(k.state)}</td>
        <td><span class="badge ${uidBlocked ? 'badge-block' : 'badge-allow'}">${uidBlocked ? 'BLOCKED (eBPF)' : 'ALLOWED'}</span></td>
        <td><strong>${esc(k.pkg)}</strong></td>
        <td class="mono">${k.uid}</td>
        <td class="mono">${esc(k.proto)}</td>
        <td style="color:var(--accent)">${esc(k.domain)}</td>
        <td class="mono">${esc(k.localIp)}:${k.localPort}</td>
        <td class="mono">${esc(k.remoteIp)}:${k.remotePort}</td>
        <td style="display:flex;gap:5px;">
          ${k.uid >= 10000 ? (uidBlocked
            ? `<button class="btn btn-green" onclick="apiCall({action:'allow_uid',uid:${k.uid}})">Allow App</button>`
            : `<button class="btn btn-red" onclick="apiCall({action:'block_uid',uid:${k.uid}})">Block App (eBPF)</button>`) : '<span style="color:var(--muted)">Protected UID</span>'}
          ${k.domain && k.domain !== '-' ? `<button class="btn btn-red" onclick="apiCall({action:'block_domain',domain:'${esc(k.domain)}'})">Block Domain</button>` : ''}
        </td>
      </tr>
    `;
  }).join('');

  // Render Apps Table
  const af = (document.getElementById('appFilter').value || '').toLowerCase();
  const appsBody = document.getElementById('appsTableBody');
  appsBody.innerHTML = s.apps.filter(a => {
    if (!af) return true;
    return (a.pkg + ' ' + a.uid).toLowerCase().includes(af);
  }).map(a => {
    return `
      <tr>
        <td><span class="badge ${a.blocked ? 'badge-block' : 'badge-allow'}">${a.blocked ? 'BLOCKED (Kernel eBPF)' : 'ALLOWED'}</span></td>
        <td class="mono">${a.uid}</td>
        <td><strong>${esc(a.pkg)}</strong></td>
        <td>${a.system ? 'System' : 'User/App'}</td>
        <td class="mono">${a.activeSockets}</td>
        <td class="mono">${a.eventsCount}</td>
        <td>
          ${a.protectedUid ? '<span style="color:var(--muted)">Protected Core UID</span>' : (
            a.blocked
              ? `<button class="btn btn-green" onclick="apiCall({action:'allow_uid',uid:${a.uid}})">✓ Allow in Kernel eBPF</button>`
              : `<button class="btn btn-red" onclick="apiCall({action:'block_uid',uid:${a.uid}})">✕ Block in Kernel eBPF</button>`
          )}
        </td>
      </tr>
    `;
  }).join('');

  // Render Domain & IP chips
  document.getElementById('domainRulesList').innerHTML = s.blockedDomains.map(d => `
    <div class="rule-chip">
      <span class="mono">${esc(d)}</span>
      <button class="btn btn-green" onclick="apiCall({action:'allow_domain',domain:'${esc(d)}'})">Remove</button>
    </div>
  `).join('');

  document.getElementById('ipRulesList').innerHTML = s.blockedIps.map(ip => `
    <div class="rule-chip">
      <span class="mono">${esc(ip)}</span>
      <button class="btn btn-green" onclick="apiCall({action:'allow_ip',ip:'${esc(ip)}'})">Remove</button>
    </div>
  `).join('');

  // Render DNS Table
  document.getElementById('dnsTableBody').innerHTML = s.dnsLog.map(d => `
    <tr>
      <td class="mono">${esc(d.time)}</td>
      <td><span class="badge ${d.blocked ? 'badge-tun' : 'badge-allow'}">${d.blocked ? 'SINKHOLED (10.254.x.y)' : 'RESOLVED'}</span></td>
      <td style="color:var(--accent);font-weight:600;">${esc(d.domain)}</td>
      <td class="mono">${esc(d.ips)}</td>
      <td>
        ${d.blocked
          ? `<button class="btn btn-green" onclick="apiCall({action:'allow_domain',domain:'${esc(d.domain)}'})">Unblock Domain</button>`
          : `<button class="btn btn-red" onclick="apiCall({action:'block_domain',domain:'${esc(d.domain)}'})">Block Domain</button>`}
      </td>
    </tr>
  `).join('');
}

refreshState();
setInterval(refreshState, 1500);
</script>
</body>
</html>
""";
}
