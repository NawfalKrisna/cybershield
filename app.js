/* CyberShield - Logika aplikasi (UI, simulasi, penyimpanan) */
(function () {
  'use strict';
  const CS = window.CyberShieldEngine;
  const KEY = 'cybershield_state_v1';

  /* ---------- Util ---------- */
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmt = n => Number(n).toLocaleString('en-US');
  const rnd = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
  const pick = a => a[rnd(0, a.length - 1)];
  const timeStr = ts => new Date(ts).toISOString().substr(11, 8);
  const dateStr = ts => new Date(ts).toISOString().substr(0, 10);
  const randIp = () => `${pick([203, 198, 185, 45, 91, 77, 104, 172, 141])}.${rnd(0, 255)}.${rnd(1, 254)}.${rnd(1, 254)}`;
  const lanIp = () => `192.168.1.${rnd(2, 250)}`;

  const PORT_NAMES = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 4444: 'Backdoor', 8080: 'HTTP-Alt' };
  const portName = p => PORT_NAMES[p] || 'TCP/' + p;

  /* ---------- State ---------- */
  function seed() {
    const now = Date.now();
    const s = {
      firewallOn: true,
      seq: { rule: 6, log: 1, bl: 4 },
      rules: [
        { id: 1, name: 'Izinkan HTTP', action: 'allow', ip: '*', port: '80', proto: 'TCP', active: true },
        { id: 2, name: 'Izinkan HTTPS', action: 'allow', ip: '*', port: '443', proto: 'TCP', active: true },
        { id: 3, name: 'Izinkan DNS', action: 'allow', ip: '*', port: '53', proto: 'UDP', active: true },
        { id: 4, name: 'Blokir Telnet', action: 'block', ip: '*', port: '23', proto: 'TCP', active: true },
        { id: 5, name: 'Izinkan SSH Admin (LAN)', action: 'allow', ip: '192.168.1.0/24', port: '22', proto: 'TCP', active: false }
      ],
      blacklist: [
        { id: 1, ip: '185.220.101.45', reason: 'Node TOR exit - aktivitas scanning', added: now - 86400000 * 3 },
        { id: 2, ip: '45.155.205.233', reason: 'Sumber brute force SSH', added: now - 86400000 * 2 },
        { id: 3, ip: '91.240.118.172', reason: 'Server C2 malware', added: now - 3600000 * 5 }
      ],
      stats: { total: 124580, allowed: 118920, blocked: 5660 },
      portBlocks: { 22: 1840, 3389: 1320, 23: 980, 445: 760, 3306: 410 },
      logs: []
    };
    const seedLogs = [
      ['185.220.101.45', 22, 'IP Blacklist - koneksi ditolak', 'block'],
      ['203.0.113.25', 443, 'Lalu lintas normal (HTTPS)', 'allow'],
      ['198.51.100.77', 3389, 'Percobaan akses RDP', 'block'],
      ['45.155.205.233', 22, 'Percobaan SSH Brute Force', 'block'],
      ['104.28.14.9', 80, 'Lalu lintas normal (HTTP)', 'allow'],
      ['141.98.10.62', 445, 'Eksploitasi SMB', 'block'],
      ['77.88.55.80', 23, 'Akses Telnet tidak sah', 'block']
    ];
    seedLogs.forEach((l, i) => s.logs.unshift({ id: s.seq.log++, ts: now - (seedLogs.length - i) * 47000, ip: l[0], port: l[1], type: l[2], action: l[3] }));
    return s;
  }

  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) { const s = JSON.parse(raw); if (s && s.rules && s.logs && s.blacklist) return s; }
    } catch (e) { /* abaikan */ }
    return seed();
  }
  let S = load();
  let saveTimer = null;
  function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      try { S.logs = S.logs.slice(0, 500); localStorage.setItem(KEY, JSON.stringify(S)); } catch (e) { /* storage penuh/diblokir */ }
    }, 250);
  }

  /* ---------- State non-persisten ---------- */
  const HIST = 60;
  const hist = Array.from({ length: HIST }, () => ({ a: rnd(180, 420), b: rnd(6, 40) }));
  let feed = [];
  let session = { allowed: 0, blocked: 0 };
  let trafficRunning = true;
  let speed = 1;
  let hitMap = {};          // IDS: riwayat koneksi per IP
  let lastHourBase = S.stats.total;
  let currentPage = 'dashboard';
  let secPackets = 0;

  /* ---------- Pemrosesan paket ---------- */
  function describe(pkt, res) {
    if (res.action === 'allow') return res.reason === 'off' ? `Firewall nonaktif - lalu lintas lolos (${portName(pkt.port)})` : `Lalu lintas normal (${portName(pkt.port)})`;
    if (res.reason === 'blacklist') return 'IP Blacklist - koneksi ditolak';
    if (res.reason === 'ids-rate') return 'DDoS / Flood terdeteksi (IDS rate limit)';
    if (res.reason === 'ids-signature') return pkt.signatureName || 'Signature serangan terdeteksi (IPS)';
    if (pkt.label) return pkt.label;
    const m = { 22: 'Percobaan SSH Brute Force', 23: 'Akses Telnet tidak sah', 21: 'Percobaan akses FTP', 3389: 'Percobaan akses RDP', 445: 'Eksploitasi SMB', 139: 'Pemindaian NetBIOS', 3306: 'Akses database eksternal', 1433: 'Akses database eksternal', 4444: 'Koneksi backdoor' };
    return m[pkt.port] || 'Port scanning (port tidak diizinkan)';
  }

  function idsRate(ip) {
    const now = Date.now();
    const arr = (hitMap[ip] = (hitMap[ip] || []).filter(t => now - t < 10000));
    arr.push(now);
    return arr.length > 12;
  }

  function autoBlacklist(ip) {
    if (S.blacklist.some(b => b.ip === ip)) return;
    S.blacklist.unshift({ id: S.seq.bl++, ip, reason: 'Auto-block IDS: rate limit terlampaui', added: Date.now() });
    toast(`IDS memasukkan ${ip} ke blacklist`, 'err');
  }

  function processPacket(pkt, opts = {}) {
    const packets = pkt.packets || rnd(20, 180);
    let res = S.firewallOn ? CS.evaluate(pkt, S) : { action: 'allow', reason: 'off', rule: null };
    if (S.firewallOn && res.action === 'allow') {
      if (pkt.signature) res = { action: 'block', reason: 'ids-signature', rule: null };
      else if (idsRate(pkt.ip)) { res = { action: 'block', reason: 'ids-rate', rule: null }; autoBlacklist(pkt.ip); }
    }
    const allowed = res.action === 'allow';
    S.stats.total += packets;
    secPackets += packets;
    if (allowed) { S.stats.allowed += packets; hist[HIST - 1].a += packets; session.allowed++; }
    else {
      S.stats.blocked += packets; hist[HIST - 1].b += packets; session.blocked++;
      S.portBlocks[pkt.port] = (S.portBlocks[pkt.port] || 0) + 1;
    }
    const entry = { ts: Date.now(), ip: pkt.ip, port: +pkt.port, proto: pkt.proto || 'TCP', type: describe(pkt, res), action: res.action, reason: res.reason, rule: res.rule ? res.rule.name : null };
    // Log: semua kejadian manual/serangan dan semua blokir dicatat; lalu lintas normal dicuplik 25%
    if (opts.force || !allowed || Math.random() < 0.25) {
      S.logs.unshift({ id: S.seq.log++, ts: entry.ts, ip: entry.ip, port: entry.port, type: entry.type, action: entry.action });
      if (S.logs.length > 500) S.logs.length = 500;
    }
    feed.unshift(entry);
    if (feed.length > 14) feed.length = 14;
    save();
    scheduleRender();
    return entry;
  }

  /* ---------- Generator traffic normal ---------- */
  const NORMAL_PORTS = [443, 443, 443, 443, 80, 80, 80, 53, 53, 8080, 25, 22, 3389, 445, 23, 3306, 21, 1433];
  function trafficTick() {
    if (!trafficRunning) return;
    const n = rnd(2, 4) * speed;
    for (let i = 0; i < n; i++) {
      const port = pick(NORMAL_PORTS);
      processPacket({ ip: Math.random() < 0.2 ? lanIp() : randIp(), port, proto: port === 53 ? 'UDP' : 'TCP' });
    }
  }

  /* ---------- Skenario serangan ---------- */
  function runAttack(kind) {
    const steps = [];
    const atk = randIp();
    switch (kind) {
      case 'portscan':
        [21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 8080].forEach(p => steps.push({ ip: atk, port: p, proto: 'TCP', packets: rnd(1, 4), label: 'Port scanning (port tidak diizinkan)' }));
        break;
      case 'ssh':
        for (let i = 0; i < 20; i++) steps.push({ ip: atk, port: 22, proto: 'TCP', packets: rnd(5, 20), label: 'Percobaan SSH Brute Force' });
        break;
      case 'ddos': {
        const bots = Array.from({ length: 6 }, randIp);
        for (let i = 0; i < 70; i++) steps.push({ ip: bots[i % 6], port: 80, proto: 'TCP', packets: rnd(300, 1500) });
        break;
      }
      case 'sqli':
        for (let i = 0; i < 5; i++) steps.push({ ip: atk, port: 80, proto: 'TCP', packets: rnd(3, 12), signature: true, signatureName: "SQL Injection terdeteksi (' OR 1=1 --)" });
        break;
      case 'c2': {
        const c2 = S.blacklist.length ? pick(S.blacklist).ip.split('/')[0] : '91.240.118.172';
        for (let i = 0; i < 6; i++) steps.push({ ip: c2, port: 4444, proto: 'TCP', packets: rnd(2, 10), label: 'Malware C2 beacon' });
        break;
      }
      case 'rdp':
        for (let i = 0; i < 8; i++) steps.push({ ip: atk, port: i % 2 ? 445 : 3389, proto: 'TCP', packets: rnd(10, 60) });
        break;
    }
    const names = { portscan: 'Port Scan', ssh: 'Brute Force SSH', ddos: 'DDoS / SYN Flood', sqli: 'SQL Injection', c2: 'Malware C2', rdp: 'Serangan RDP/SMB' };
    toast(`Simulasi serangan dimulai: ${names[kind]}`, 'err');
    const gap = kind === 'ddos' ? 45 : 130;
    steps.forEach((st, i) => setTimeout(() => processPacket(st, { force: true }), i * gap));
  }

  /* ---------- Render ---------- */
  let renderPending = false;
  function scheduleRender() {
    if (renderPending) return;
    renderPending = true;
    requestAnimationFrame(() => { renderPending = false; renderAll(); });
  }

  function activeRules() { return S.rules.filter(r => r.active); }

  function renderAll() {
    renderTop(); renderStats();
    if (currentPage === 'dashboard') { renderCharts(); renderAlerts(); }
    if (currentPage === 'simulation') renderFeed();
    if (currentPage === 'logs') renderLogs();
  }

  function renderTop() {
    const on = S.firewallOn;
    $('#fwStatus').textContent = on ? 'AKTIF (ALLOW-LIST)' : 'NONAKTIF';
    $('#fwStatus').className = on ? 'green' : 'red';
    $('#fwDot').className = 'dot ' + (on ? 'green' : 'red');
    $('#idsStatus').textContent = on ? 'ONLINE' : 'OFFLINE';
    $('#idsStatus').className = on ? 'cyan' : 'red';
    $('#idsDot').className = 'dot ' + (on ? 'cyan' : 'red');
    const btn = $('#btnFirewallToggle');
    btn.classList.toggle('off', !on);
    $('span', btn).textContent = on ? 'Matikan Firewall' : 'Hidupkan Firewall';

    const recent = hist.slice(-20).reduce((t, h) => ({ a: t.a + h.a, b: t.b + h.b }), { a: 0, b: 0 });
    const ratio = recent.b / Math.max(1, recent.a + recent.b);
    let lvl = 'RENDAH', cls = 'badge-green';
    if (!on) { lvl = 'KRITIS'; cls = 'badge-red'; }
    else if (ratio > 0.4) { lvl = 'TINGGI'; cls = 'badge-red'; }
    else if (ratio > 0.15) { lvl = 'SEDANG'; cls = 'badge-amber'; }
    $('#threatLevel').textContent = lvl; $('#threatLevel').className = cls;

    $('#navRuleCount').textContent = S.rules.length;
    $('#navLive').classList.toggle('off', !trafficRunning);
  }

  function renderStats() {
    const st = S.stats;
    $('#stTotal').textContent = fmt(st.total);
    $('#stAllowed').textContent = fmt(st.allowed);
    $('#stBlocked').textContent = fmt(st.blocked);
    $('#stRate').textContent = (st.total ? (st.allowed / st.total * 100) : 0).toFixed(1) + '%';
    const ar = activeRules();
    $('#stRules').textContent = ar.length;
    $('#stRulesNote').textContent = `${ar.filter(r => r.action === 'allow').length} Allow / ${ar.filter(r => r.action === 'block').length} Block`;
    const growth = st.total - lastHourBase;
    const pct = lastHourBase ? (growth / lastHourBase * 100) : 0;
    $('#stTotalNote').innerHTML = `&#8599; +${pct.toFixed(1)}% sesi ini`;
    if (currentPage === 'simulation') {
      $('#simAllowed').textContent = `${fmt(session.allowed)} diizinkan`;
      $('#simBlocked').textContent = `${fmt(session.blocked)} diblokir`;
    }
  }

  /* Grafik traffic (canvas) */
  function renderCharts() {
    drawTraffic();
    const entries = Object.entries(S.portBlocks).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const max = entries.length ? entries[0][1] : 1;
    $('#portBars').innerHTML = entries.length ? entries.map(([p, v]) =>
      `<div class="pb-row"><span class="pb-name">${esc(p)} (${esc(portName(p))})</span><div class="pb-track"><div class="pb-fill" style="width:${(v / max * 100).toFixed(1)}%"></div></div><span class="pb-val">${fmt(v)}</span></div>`).join('') : '<div class="empty">Belum ada data</div>';
  }

  function drawTraffic() {
    const cv = $('#trafficChart');
    if (!cv || cv.offsetParent === null) return;
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth, h = cv.clientHeight;
    if (cv.width !== w * dpr || cv.height !== h * dpr) { cv.width = w * dpr; cv.height = h * dpr; }
    const c = cv.getContext('2d');
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.clearRect(0, 0, w, h);
    const padL = 42, padB = 22, padT = 8, padR = 8;
    const gw = w - padL - padR, gh = h - padB - padT;
    const max = Math.max(100, ...hist.map(x => x.a + 0), ...hist.map(x => x.b)) * 1.15;
    c.font = '10px monospace'; c.fillStyle = '#6b7d96'; c.strokeStyle = '#142033'; c.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padT + gh - (gh * i / 4);
      c.beginPath(); c.moveTo(padL, y); c.lineTo(w - padR, y); c.stroke();
      c.textAlign = 'right'; c.fillText(Math.round(max * i / 4), padL - 6, y + 3);
    }
    c.textAlign = 'center';
    [0, 15, 30, 45, 59].forEach(i => c.fillText(i === 59 ? 'now' : `-${59 - i}s`, padL + gw * i / (HIST - 1), h - 6));
    const line = (key, color, fill) => {
      c.beginPath();
      hist.forEach((p, i) => {
        const x = padL + gw * i / (HIST - 1), y = padT + gh - gh * p[key] / max;
        i ? c.lineTo(x, y) : c.moveTo(x, y);
      });
      c.strokeStyle = color; c.lineWidth = 2; c.lineJoin = 'round'; c.stroke();
      c.lineTo(padL + gw, padT + gh); c.lineTo(padL, padT + gh); c.closePath();
      const g = c.createLinearGradient(0, padT, 0, padT + gh);
      g.addColorStop(0, fill); g.addColorStop(1, 'rgba(0,0,0,0)');
      c.fillStyle = g; c.fill();
    };
    line('a', '#34d399', 'rgba(52,211,153,.22)');
    line('b', '#fb4b6b', 'rgba(251,75,107,.25)');
  }

  function renderAlerts() {
    const rows = S.logs.filter(l => l.action === 'block').slice(0, 5);
    $('#alertBody').innerHTML = rows.length ? rows.map(l =>
      `<tr><td class="mono">${timeStr(l.ts)}</td><td class="mono">${esc(l.ip)}</td><td class="mono">${l.port}</td><td>${esc(l.type)}</td><td><span class="tag block">DIBLOKIR</span></td></tr>`).join('')
      : '<tr><td colspan="5" class="empty">Belum ada peringatan</td></tr>';
  }

  function renderRules() {
    $('#rulesBody').innerHTML = S.rules.length ? S.rules.map(r =>
      `<tr class="${r.active ? '' : 'inactive'}">
        <td><label class="switch"><input type="checkbox" data-toggle="${r.id}" ${r.active ? 'checked' : ''}><span class="slider"></span></label></td>
        <td>${esc(r.name)}</td>
        <td><span class="tag ${r.action}">${r.action === 'allow' ? 'IZINKAN' : 'BLOKIR'}</span></td>
        <td class="mono">${esc(r.ip === '*' ? 'Semua IP (*)' : r.ip)}</td>
        <td class="mono">${esc(r.port === '*' ? 'Semua (*)' : r.port)}</td>
        <td><span class="tag neutral">${esc(r.proto)}</span></td>
        <td><button class="btn btn-sm btn-danger" data-delrule="${r.id}"><svg class="ic"><use href="#i-trash"/></svg>Hapus</button></td>
      </tr>`).join('') : '<tr><td colspan="7" class="empty">Belum ada aturan. Klik "Tambah Aturan".</td></tr>';
  }

  function renderFeed() {
    $('#feedBody').innerHTML = feed.length ? feed.map((e, i) =>
      `<tr class="${i === 0 ? 'flash' : ''}"><td class="mono">${timeStr(e.ts)}</td><td class="mono">${esc(e.ip)}</td><td class="mono">${e.port}</td><td>${esc(e.type)}</td><td><span class="tag ${e.action}">${e.action === 'allow' ? 'DIIZINKAN' : 'DIBLOKIR'}</span></td></tr>`).join('')
      : '<tr><td colspan="5" class="empty">Menunggu lalu lintas...</td></tr>';
  }

  function filteredLogs() {
    const q = $('#logSearch').value.trim().toLowerCase();
    const f = $('#logFilter').value;
    return S.logs.filter(l => (f === 'all' || l.action === f) &&
      (!q || l.ip.includes(q) || String(l.port).includes(q) || l.type.toLowerCase().includes(q)));
  }

  function renderLogs() {
    const rows = filteredLogs();
    $('#logSummary').textContent = `${rows.length} dari ${S.logs.length} kejadian tercatat (maks. 500 terakhir)`;
    const blIps = new Set(S.blacklist.map(b => b.ip));
    $('#logBody').innerHTML = rows.length ? rows.slice(0, 200).map(l =>
      `<tr><td class="mono">${dateStr(l.ts)} ${timeStr(l.ts)}</td><td class="mono">${esc(l.ip)}</td><td class="mono">${l.port}</td><td>${esc(l.type)}</td>
       <td><span class="tag ${l.action}">${l.action === 'allow' ? 'DIIZINKAN' : 'DIBLOKIR'}</span></td>
       <td>${l.action === 'block' && !blIps.has(l.ip) ? `<button class="btn btn-sm" data-bl="${esc(l.ip)}">+ Blacklist</button>` : ''}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">Tidak ada log yang cocok.</td></tr>';
  }

  function renderBlacklist() {
    $('#blBody').innerHTML = S.blacklist.length ? S.blacklist.map(b =>
      `<tr><td class="mono">${esc(b.ip)}</td><td>${esc(b.reason || '-')}</td><td class="mono">${dateStr(b.added)} ${timeStr(b.added)}</td>
       <td><button class="btn btn-sm btn-danger" data-delbl="${b.id}"><svg class="ic"><use href="#i-trash"/></svg>Hapus</button></td></tr>`).join('')
      : '<tr><td colspan="4" class="empty">Blacklist kosong.</td></tr>';
  }

  /* ---------- Sumber daya sistem + jam ---------- */
  function tick() {
    hist.shift(); hist.push({ a: rnd(120, 300) * (trafficRunning ? 1 : 0.1), b: rnd(2, 25) * (trafficRunning ? 1 : 0.1) });
    const load = Math.min(95, 10 + secPackets / 220 + rnd(0, 6));
    const mem = Math.min(90, 38 + Math.round(load / 8) + rnd(0, 2));
    const bw = (0.8 + secPackets / 2500 + Math.random() * 0.6).toFixed(1);
    secPackets = 0;
    $('#cpuVal').textContent = Math.round(load) + '%'; $('#cpuBar').style.width = load + '%';
    $('#memVal').textContent = mem + '%'; $('#memBar').style.width = mem + '%';
    $('#bwVal').textContent = bw + ' MB/s';
    $('#clock').textContent = new Date().toISOString().substr(11, 8) + ' UTC';
    trafficTick();
    renderAll();
  }

  /* ---------- Toast ---------- */
  function toast(msg, type) {
    const t = document.createElement('div');
    t.className = 'toast ' + (type || '');
    t.textContent = msg;
    $('#toasts').appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }

  /* ---------- Navigasi ---------- */
  function go(page) {
    if (!$('#page-' + page)) page = 'dashboard';
    currentPage = page;
    $$('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === page));
    if (page === 'rules') renderRules();
    if (page === 'blacklist') renderBlacklist();
    renderAll();
    if (page === 'dashboard') requestAnimationFrame(drawTraffic);
  }
  window.addEventListener('hashchange', () => go(location.hash.slice(1)));

  /* ---------- Event handler ---------- */
  $('#btnFirewallToggle').addEventListener('click', () => {
    S.firewallOn = !S.firewallOn; save(); renderAll();
    toast(S.firewallOn ? 'Firewall diaktifkan' : 'Firewall dinonaktifkan - semua lalu lintas lolos', S.firewallOn ? 'ok' : 'err');
  });

  // Aturan
  const dlg = $('#ruleDialog');
  $('#btnAddRule').addEventListener('click', () => { $('#ruleForm').reset(); $('#rIp').value = '*'; $('#rPort').value = '*'; $('#ruleError').textContent = ''; dlg.showModal(); $('#rName').focus(); });
  $('#ruleCancel').addEventListener('click', () => dlg.close());
  $('#ruleForm').addEventListener('submit', e => {
    e.preventDefault();
    const name = $('#rName').value.trim(), ip = $('#rIp').value.trim() || '*', port = $('#rPort').value.trim() || '*';
    const err = $('#ruleError');
    if (!name) { err.textContent = 'Nama aturan wajib diisi.'; return; }
    if (!CS.isValidIPRule(ip)) { err.textContent = 'Alamat IP tidak valid. Gunakan *, IP (10.0.0.5) atau CIDR (10.0.0.0/24).'; return; }
    if (!CS.isValidPort(port)) { err.textContent = 'Port tidak valid. Gunakan *, angka 1-65535, atau rentang (1000-2000).'; return; }
    S.rules.push({ id: S.seq.rule++, name, action: $('#rAction').value, ip, port, proto: $('#rProto').value, active: true });
    save(); dlg.close(); renderRules(); renderAll();
    toast(`Aturan "${name}" ditambahkan`, 'ok');
  });
  $('#rulesBody').addEventListener('change', e => {
    const id = +e.target.dataset.toggle; if (!id) return;
    const r = S.rules.find(x => x.id === id); if (!r) return;
    r.active = e.target.checked; save(); renderRules(); renderAll();
    toast(`Aturan "${r.name}" ${r.active ? 'diaktifkan' : 'dinonaktifkan'}`, r.active ? 'ok' : '');
  });
  $('#rulesBody').addEventListener('click', e => {
    const b = e.target.closest('[data-delrule]'); if (!b) return;
    const r = S.rules.find(x => x.id === +b.dataset.delrule);
    if (!r || !confirm(`Hapus aturan "${r.name}"?`)) return;
    S.rules = S.rules.filter(x => x !== r); save(); renderRules(); renderAll();
    toast('Aturan dihapus');
  });

  // Simulasi
  $('#btnTraffic').addEventListener('click', () => {
    trafficRunning = !trafficRunning;
    const b = $('#btnTraffic');
    $('span', b).textContent = trafficRunning ? 'Jeda Traffic' : 'Jalankan Traffic';
    $('use', b).setAttribute('href', trafficRunning ? '#i-pause' : '#i-play');
    renderAll();
  });
  $('#speed').addEventListener('change', e => { speed = +e.target.value; });
  $$('[data-attack]').forEach(b => b.addEventListener('click', () => runAttack(b.dataset.attack)));
  $('#testForm').addEventListener('submit', e => {
    e.preventDefault();
    const ip = $('#tIp').value.trim(), port = $('#tPort').value.trim(), proto = $('#tProto').value;
    const box = $('#testResult');
    box.hidden = false;
    if (!CS.isValidIP(ip) || !/^\d+$/.test(port) || +port < 1 || +port > 65535) {
      box.className = 'test-result block';
      box.innerHTML = '<div class="big red">INPUT TIDAK VALID</div>Masukkan IPv4 yang valid dan port 1-65535.';
      return;
    }
    const en = processPacket({ ip, port: +port, proto, packets: 1 }, { force: true });
    const why = {
      rule: `Cocok dengan aturan: <b>${esc(en.rule || '')}</b>`,
      blacklist: 'IP berada di <b>Blacklist</b>',
      default: 'Tidak ada aturan IZINKAN yang cocok (<b>default deny</b>)',
      'ids-signature': 'Signature serangan terdeteksi oleh IPS',
      'ids-rate': 'Terlalu banyak koneksi dalam waktu singkat (IDS rate limit)',
      off: 'Firewall sedang <b>nonaktif</b>'
    }[en.reason] || '';
    const ok = en.action === 'allow';
    box.className = 'test-result ' + en.action;
    box.innerHTML = `<div class="big ${ok ? 'green' : 'red'}">${ok ? 'KONEKSI DIIZINKAN' : 'KONEKSI DIBLOKIR'}</div>${esc(ip)}:${port}/${proto} &rarr; ${why}<br><span class="mono" style="color:#7d8da3">Tercatat di Log Keamanan.</span>`;
  });

  // Log
  $('#logSearch').addEventListener('input', renderLogs);
  $('#logFilter').addEventListener('change', renderLogs);
  $('#btnClearLogs').addEventListener('click', () => {
    if (!confirm('Hapus seluruh log keamanan?')) return;
    S.logs = []; save(); renderLogs(); toast('Log dihapus');
  });
  $('#btnExport').addEventListener('click', () => {
    const rows = filteredLogs();
    const csv = ['waktu,ip_sumber,port_tujuan,jenis_aktivitas,tindakan'].concat(rows.map(l =>
      [`${dateStr(l.ts)} ${timeStr(l.ts)}`, l.ip, l.port, `"${l.type.replace(/"/g, '""')}"`, l.action === 'allow' ? 'DIIZINKAN' : 'DIBLOKIR'].join(','))).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'cybershield_log.csv'; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $('#logBody').addEventListener('click', e => {
    const b = e.target.closest('[data-bl]'); if (!b) return;
    addBlacklist(b.dataset.bl, 'Ditambahkan dari Log Keamanan');
    renderLogs();
  });

  // Blacklist
  function addBlacklist(ip, reason) {
    if (S.blacklist.some(b => b.ip === ip)) { toast('IP sudah ada di blacklist', 'err'); return false; }
    S.blacklist.unshift({ id: S.seq.bl++, ip, reason: reason || '', added: Date.now() });
    save(); toast(`${ip} ditambahkan ke blacklist`, 'ok'); renderAll();
    return true;
  }
  $('#blForm').addEventListener('submit', e => {
    e.preventDefault();
    const ip = $('#blIp').value.trim(), err = $('#blError');
    if (!ip || ip === '*' || !CS.isValidIPRule(ip)) { err.textContent = 'Masukkan alamat IP (atau CIDR) yang valid.'; return; }
    err.textContent = '';
    if (addBlacklist(ip, $('#blReason').value.trim())) { $('#blIp').value = ''; $('#blReason').value = ''; renderBlacklist(); }
  });
  $('#blBody').addEventListener('click', e => {
    const b = e.target.closest('[data-delbl]'); if (!b) return;
    const item = S.blacklist.find(x => x.id === +b.dataset.delbl);
    if (!item) return;
    S.blacklist = S.blacklist.filter(x => x !== item); delete hitMap[item.ip];
    save(); renderBlacklist(); toast(`${item.ip} dihapus dari blacklist`);
  });

  window.addEventListener('resize', () => { if (currentPage === 'dashboard') drawTraffic(); });

  // Reset data lewat konsol: CyberShieldReset()
  window.CyberShieldReset = () => { localStorage.removeItem(KEY); location.reload(); };

  /* ---------- Mulai ---------- */
  go(location.hash.slice(1) || 'dashboard');
  setInterval(tick, 1000);
  tick();
})();
