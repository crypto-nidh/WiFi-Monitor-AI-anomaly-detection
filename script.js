// ── State ─────────────────────────────────────────────────────────────────────
let allDevices = [];
let allEvents = [];
let selectedMac = null;
let prevEventCount = 0;
let toastTimer = null;
let mapAnimFrame = null;

// ── Demo Data Generator ───────────────────────────────────────────────────────
function generateDemoData() {
    const gateway = "192.168.1.1";
    const now = new Date().toISOString();

    const deviceDefs = [
        { ip: "192.168.1.1", mac: "FC:FB:FB:12:34:56", hostname: "router.local", vendor: "Cisco", isGateway: true, ports: [80, 443, 22, 53, 8080] },
        { ip: "192.168.1.101", mac: "A4:C3:F0:AA:BB:CC", hostname: "macbook-pro.local", vendor: "Apple", isGateway: false, ports: [22, 5900] },
        { ip: "192.168.1.102", mac: "B8:27:EB:DE:AD:01", hostname: "raspberrypi.local", vendor: "Raspberry Pi", isGateway: false, ports: [22, 80, 5000, 3306, 5432, 6379, 8080, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 443, 21, 23, 25] },
        { ip: "192.168.1.103", mac: "00:23:F8:AB:12:34", hostname: "android-phone", vendor: "Huawei", isGateway: false, ports: [8080] },
        { ip: "192.168.1.104", mac: "DE:AD:BE:EF:CA:FE", hostname: "unknown-device", vendor: "Unknown", isGateway: false, ports: [4444, 1337, 31337] },
        { ip: "192.168.1.105", mac: "54:89:98:77:66:55", hostname: "huawei-tablet", vendor: "Huawei", isGateway: false, ports: [80, 443] },
        { ip: "192.168.1.106", mac: "00:15:5D:11:22:33", hostname: "windows-pc", vendor: "Microsoft", isGateway: false, ports: [135, 445, 3389] },
    ];

    // Compute threat scores
    function threatScore(dev) {
        let s = 0;
        // Suspicious MAC (locally administered bit)
        const firstOctet = parseInt(dev.mac.split(':')[0], 16);
        if (firstOctet & 0x02) s += 25;
        // Many open ports
        if (dev.ports.length > 10) s += 35;
        // Unknown vendor
        if (dev.vendor === "Unknown") s += 20;
        // Add some AI anomaly noise
        s += Math.random() * 15;
        return Math.min(Math.round(s), 100);
    }

    function anomalyScore(dev) {
        if (dev.ports.length > 10) return 0.7 + Math.random() * 0.2;
        if (dev.vendor === "Unknown") return 0.6 + Math.random() * 0.2;
        if (firstOctetSuspicious(dev.mac)) return 0.4 + Math.random() * 0.2;
        return Math.random() * 0.3;
    }

    function firstOctetSuspicious(mac) {
        return (parseInt(mac.split(':')[0], 16) & 0x02) !== 0;
    }

    function flags(dev) {
        const f = [];
        if (dev.isGateway) f.push("gateway");
        if (parseInt(dev.mac.split(':')[0], 16) & 0x02) f.push("Suspicious MAC");
        if (dev.ports.length > 10) f.push("Port Scan");
        if (dev.vendor === "Unknown") f.push("Unknown Vendor");
        return f;
    }

    const devices = deviceDefs.map(d => ({
        mac: d.mac,
        ip: d.ip,
        hostname: d.hostname,
        vendor: d.vendor,
        first_seen: now,
        last_seen: now,
        packets_sent: Math.floor(Math.random() * 50000),
        packets_recv: Math.floor(Math.random() * 80000),
        bytes_sent: Math.floor(Math.random() * 5000000),
        bytes_recv: Math.floor(Math.random() * 8000000),
        open_ports: d.ports,
        threat_score: threatScore(d),
        flags: flags(d),
        is_gateway: d.isGateway,
        is_new: Math.random() < 0.15,
        anomaly_score: anomalyScore(d),
    }));

    const events = [{
            event_id: "ev001",
            timestamp: new Date(Date.now() - 120000).toISOString(),
            threat_type: "Port Scan Detected",
            severity: "high",
            source_mac: "B8:27:EB:DE:AD:01",
            source_ip: "192.168.1.102",
            description: "Device raspberrypi.local has 19 open ports — possible reconnaissance or compromised host.",
            recommendation: "Review running services. Disable unused ports. Consider network isolation.",
        },
        {
            event_id: "ev002",
            timestamp: new Date(Date.now() - 60000).toISOString(),
            threat_type: "MAC Randomization / Spoofing",
            severity: "medium",
            source_mac: "DE:AD:BE:EF:CA:FE",
            source_ip: "192.168.1.104",
            description: "Device unknown-device uses locally-administered MAC address — identity may be spoofed or randomized.",
            recommendation: "Verify device identity. Enable 802.1X authentication to require certificates.",
        },
        {
            event_id: "ev003",
            timestamp: new Date(Date.now() - 30000).toISOString(),
            threat_type: "Suspicious Ports",
            severity: "critical",
            source_mac: "DE:AD:BE:EF:CA:FE",
            source_ip: "192.168.1.104",
            description: "Ports 4444, 1337, 31337 are open — commonly used by Metasploit and backdoor shells.",
            recommendation: "Immediately isolate device. Run malware scan. Block at firewall.",
        },
        {
            event_id: "ev004",
            timestamp: new Date(Date.now() - 10000).toISOString(),
            threat_type: "AI Anomaly Alert",
            severity: "medium",
            source_mac: "00:15:5D:11:22:33",
            source_ip: "192.168.1.106",
            description: "AI model detected abnormal traffic pattern from windows-pc — 3.2σ deviation from baseline.",
            recommendation: "Inspect outbound connections. Check for unusual processes or scheduled tasks.",
        },
    ];

    return {
        devices,
        events,
        stats: {
            total_devices: devices.length,
            new_devices: devices.filter(d => d.is_new).length,
            threats_detected: devices.filter(d => d.threat_score > 30).length,
            packets_per_second: (Math.random() * 800 + 200).toFixed(1),
            bytes_per_second: (Math.random() * 500000 + 100000).toFixed(0),
            anomalies: devices.filter(d => d.anomaly_score > 0.5).length,
            scan_time: now,
            gateway_ip: gateway,
            ssid: "HomeNetwork-5G",
            security: "WPA3",
        }
    };
}

// ── Rendering ─────────────────────────────────────────────────────────────────
function renderStats(stats) {
    document.getElementById('stat-devices').textContent = stats.total_devices;
    document.getElementById('stat-threats').textContent = stats.threats_detected;
    document.getElementById('stat-anomalies').textContent = stats.anomalies;
    document.getElementById('stat-pps').textContent = Math.round(stats.packets_per_second);
    document.getElementById('stat-sec').textContent = stats.security || "WPA3";
    document.getElementById('last-scan-time').textContent = new Date(stats.scan_time).toLocaleTimeString();
}

function scoreClass(score) {
    if (score > 60) return 'high';
    if (score > 30) return 'med';
    return 'low';
}

function renderDevices(devices) {
    const tbody = document.getElementById('device-tbody');
    document.getElementById('device-count').textContent = `${devices.length} devices`;

    tbody.innerHTML = devices.sort((a, b) => b.threat_score - a.threat_score).map(d => {
        const sc = scoreClass(d.threat_score);
        const rowClass = sc === 'high' ? 'threat-high' : sc === 'med' ? 'threat-medium' : '';
        const selected = d.mac === selectedMac ? 'selected' : '';
        const flagBadges = d.flags.map(f => `<span class="badge badge-threat">${f}</span>`).join('');
        const newBadge = d.is_new ? '<span class="badge badge-new">NEW</span>' : '';
        const gwBadge = d.is_gateway ? '<span class="badge badge-gw">GW</span>' : '';
        const anomBadge = d.anomaly_score > 0.5 ? '<span class="badge badge-anomaly">AI⚠</span>' : '';

        return `<tr class="${rowClass} ${selected}" onclick="selectDevice('${d.mac}')">
      <td>
        <div class="device-ip">${d.ip}</div>
        <div class="device-mac">${d.mac}</div>
      </td>
      <td class="device-hostname">${d.hostname}</td>
      <td class="device-vendor">${d.vendor}</td>
      <td>
        <div class="score-wrap">
          <div class="score-bar">
            <div class="score-fill ${sc}" style="width:${d.threat_score}%"></div>
          </div>
          <span class="score-num ${sc}">${Math.round(d.threat_score)}</span>
        </div>
      </td>
      <td>${gwBadge}${newBadge}${anomBadge}${flagBadges}</td>
    </tr>`;
    }).join('');
}

function renderEvents(events) {
    const list = document.getElementById('events-list');
    document.getElementById('event-badge').textContent = events.length;

    if (!events.length) {
        list.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:150px;color:var(--text3);font-size:11px;font-family:var(--mono);">No events — network looks clean ✓</div>`;
        return;
    }

    // Show toast for new critical events
    if (events.length > prevEventCount) {
        const newest = events[0];
        if (newest.severity === 'critical' || newest.severity === 'high') {
            showToast(newest.threat_type, newest.description);
        }
    }
    prevEventCount = events.length;

    list.innerHTML = events.map(e => `
    <div class="event-item">
      <div class="event-header">
        <div class="sev-dot ${e.severity}"></div>
        <span class="event-type">${e.threat_type}</span>
        <span class="event-sev ${e.severity}">${e.severity}</span>
      </div>
      <div class="event-desc">${e.description}</div>
      <div class="event-rec">💡 ${e.recommendation}</div>
      <div class="event-meta">
        <span class="event-meta-item">🖥 ${e.source_ip}</span>
        <span class="event-meta-item">🕐 ${new Date(e.timestamp).toLocaleTimeString()}</span>
      </div>
    </div>
  `).join('');
}

function renderDeviceDetail(mac) {
    const dev = allDevices.find(d => d.mac === mac);
    if (!dev) return;

    const sc = scoreClass(dev.threat_score);
    const portTags = dev.open_ports.map(p => `<span class="port-tag">${p}</span>`).join('');
    const bytes2mb = b => (b / 1048576).toFixed(2);

    document.getElementById('device-detail').innerHTML = `
    <div class="detail-section">
      <div class="detail-section-title">Identity</div>
      <div class="detail-row"><span class="detail-key">IP Address</span><span class="detail-val">${dev.ip}</span></div>
      <div class="detail-row"><span class="detail-key">MAC Address</span><span class="detail-val">${dev.mac}</span></div>
      <div class="detail-row"><span class="detail-key">Hostname</span><span class="detail-val">${dev.hostname}</span></div>
      <div class="detail-row"><span class="detail-key">Vendor</span><span class="detail-val">${dev.vendor}</span></div>
      <div class="detail-row"><span class="detail-key">Role</span><span class="detail-val">${dev.is_gateway ? '🌐 Gateway' : '💻 Client'}</span></div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Traffic</div>
      <div class="detail-row"><span class="detail-key">Sent</span><span class="detail-val">${bytes2mb(dev.bytes_sent)} MB</span></div>
      <div class="detail-row"><span class="detail-key">Received</span><span class="detail-val">${bytes2mb(dev.bytes_recv)} MB</span></div>
      <div class="detail-row"><span class="detail-key">Packets TX</span><span class="detail-val">${dev.packets_sent.toLocaleString()}</span></div>
      <div class="detail-row"><span class="detail-key">Packets RX</span><span class="detail-val">${dev.packets_recv.toLocaleString()}</span></div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Threat Analysis</div>
      <div class="detail-row">
        <span class="detail-key">Threat Score</span>
        <span class="detail-val score-num ${sc}">${Math.round(dev.threat_score)} / 100</span>
      </div>
      <div style="height:6px;background:var(--surface2);border-radius:3px;overflow:hidden;margin:6px 0;">
        <div style="height:100%;width:${dev.threat_score}%;background:linear-gradient(90deg,var(--green),var(--yellow),var(--red));border-radius:3px;transition:width 0.8s"></div>
      </div>

      <div class="detail-section-title" style="margin-top:12px">AI Anomaly Score</div>
      <div class="ai-meter">
        <div class="ai-meter-bar">
          <div class="ai-meter-fill" style="width:${Math.round(dev.anomaly_score * 100)}%"></div>
        </div>
        <div class="ai-meter-labels">
          <span>Normal</span>
          <span style="color:${dev.anomaly_score > 0.5 ? 'var(--red2)' : 'var(--text3)'}">
            ${(dev.anomaly_score * 100).toFixed(0)}%
          </span>
          <span>Anomalous</span>
        </div>
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Open Ports (${dev.open_ports.length})</div>
      <div class="port-list">${portTags || '<span style="color:var(--text3);font-size:11px">None detected</span>'}</div>
    </div>

    ${dev.flags.length ? `
    <div class="detail-section">
      <div class="detail-section-title">Active Flags</div>
      <div>${dev.flags.map(f => `<span class="badge badge-threat" style="margin:3px">${f}</span>`).join('')}</div>
    </div>
    ` : ''}
  `;
        }

        // ── Network Map ───────────────────────────────────────────────────────────────
        function drawNetworkMap() {
            const canvas = document.getElementById('net-canvas');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const W = canvas.offsetWidth;
            const H = 320;
            canvas.width = W;
            canvas.height = H;

            ctx.clearRect(0, 0, W, H);

            const gateway = allDevices.find(d => d.is_gateway) || allDevices[0];
            if (!gateway) return;

            const cx = W / 2, cy = 70;
            const clients = allDevices.filter(d => !d.is_gateway);
            const radius = Math.min(W * 0.35, 200);

            // Draw connections
            clients.forEach((dev, i) => {
                const angle = (i / clients.length) * Math.PI * 2 - Math.PI / 2;
                const x = cx + Math.cos(angle) * radius;
                const y = cy + 140 + Math.sin(angle) * 110;

                const sc = scoreClass(dev.threat_score);
                const lineColor = sc === 'high' ? '#ef4444' : sc === 'med' ? '#f59e0b' : '#3b82f6';

                ctx.beginPath();
                ctx.moveTo(cx, cy);
                ctx.lineTo(x, y);
                ctx.strokeStyle = lineColor + '44';
                ctx.lineWidth = 1.5;
                ctx.setLineDash([4, 4]);
                ctx.stroke();
                ctx.setLineDash([]);
            });

            // Draw gateway
            ctx.beginPath();
            ctx.arc(cx, cy, 22, 0, Math.PI * 2);
            ctx.fillStyle = '#1d4ed8';
            ctx.fill();
            ctx.strokeStyle = '#3b82f6';
            ctx.lineWidth = 2;
            ctx.stroke();
            ctx.fillStyle = '#e2e8f0';
            ctx.font = '18px sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('🌐', cx, cy);
            ctx.font = '9px JetBrains Mono, monospace';
            ctx.fillStyle = '#94a3b8';
            ctx.fillText(gateway.ip, cx, cy + 30);

            // Draw clients
            clients.forEach((dev, i) => {
                const angle = (i / clients.length) * Math.PI * 2 - Math.PI / 2;
                const x = cx + Math.cos(angle) * radius;
                const y = cy + 140 + Math.sin(angle) * 110;

                const sc = scoreClass(dev.threat_score);
                const fillColor = sc === 'high' ? '#7f1d1d' : sc === 'med' ? '#78350f' : '#1e3a5f';
                const strokeColor = sc === 'high' ? '#ef4444' : sc === 'med' ? '#f59e0b' : '#3b82f6';

                ctx.beginPath();
                ctx.arc(x, y, 16, 0, Math.PI * 2);
                ctx.fillStyle = fillColor;
                ctx.fill();
                ctx.strokeStyle = strokeColor;
                ctx.lineWidth = sc === 'high' ? 2 : 1;
                ctx.stroke();

                const icon = dev.vendor === 'Apple' ? '💻' : dev.vendor === 'Raspberry Pi' ? '🍓' :
                    dev.vendor === 'Unknown' ? '❓' : dev.is_gateway ? '🌐' : '📱';
                ctx.font = '12px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(icon, x, y);

                // Hostname label
                ctx.font = '8px JetBrains Mono, monospace';
                ctx.fillStyle = '#64748b';
                ctx.textAlign = 'center';
                const label = dev.hostname.length > 14 ? dev.hostname.slice(0, 12) + '…' : dev.hostname;
                ctx.fillText(label, x, y + 24);
            });
        }

        // ── UI Helpers ────────────────────────────────────────────────────────────────
        function selectDevice(mac) {
            selectedMac = mac;
            renderDevices(allDevices);
            renderDeviceDetail(mac);
            switchTab('detail', document.querySelectorAll('.tab')[1]);
        }

        function switchTab(name, el) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            el.classList.add('active');
            document.getElementById('tab-' + name).classList.add('active');
            if (name === 'map') setTimeout(drawNetworkMap, 50);
        }

        function showToast(type, msg) {
            clearTimeout(toastTimer);
            document.getElementById('toast-type').textContent = '🚨 ' + type.toUpperCase();
            document.getElementById('toast-msg').textContent = msg.slice(0, 120);
            const t = document.getElementById('toast');
            t.classList.add('show');
            toastTimer = setTimeout(() => t.classList.remove('show'), 5000);
        }

        function triggerScan() {
            const btn = document.getElementById('scan-btn');
            btn.classList.add('scanning');
            btn.textContent = '◌ Scanning...';
            setTimeout(() => {
                loadData();
                btn.classList.remove('scanning');
                btn.textContent = '⟳ Scan Now';
            }, 1800);
        }

        // ── Data Loading ──────────────────────────────────────────────────────────────
        function loadData() {
            // Try real API first, fall back to demo data
            fetch('/api/snapshot')
                .then(r => r.json())
                .then(applySnapshot)
                .catch(() => {
                    // Demo mode
                    const demo = generateDemoData();
                    applySnapshot(demo);
                });
        }

        function applySnapshot(data) {
            allDevices = data.devices || [];
            allEvents = data.events || [];
            renderStats(data.stats || {});
            renderDevices(allDevices);
            renderEvents(allEvents);
            if (selectedMac) renderDeviceDetail(selectedMac);
        }

        // ── Init ──────────────────────────────────────────────────────────────────────
        loadData();
        setInterval(loadData, 10000);

        // Initial toast after 3s for dramatic effect
        setTimeout(() => {
            if (allEvents.length) {
                const critical = allEvents.find(e => e.severity === 'critical' || e.severity === 'high');
                if (critical) showToast(critical.threat_type, critical.description);
            }
        }, 3000);