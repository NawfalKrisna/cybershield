/* CyberShield - Firewall Engine
 * Logika murni (tanpa DOM) agar bisa dipakai di browser dan diuji dengan Node.js.
 */
(function (root) {
  'use strict';
  const E = {};

  E.isValidIP = function (ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every(n => +n >= 0 && +n <= 255);
  };

  // Aturan IP: "*" (semua), IP tunggal, atau CIDR (mis. 192.168.1.0/24)
  E.isValidIPRule = function (v) {
    if (v === '*') return true;
    if (E.isValidIP(v)) return true;
    const m = /^([\d.]+)\/(\d{1,2})$/.exec(v);
    return !!m && E.isValidIP(m[1]) && +m[2] >= 0 && +m[2] <= 32;
  };

  // Aturan port: "*", angka 1-65535, atau rentang "1000-2000"
  E.isValidPort = function (v) {
    if (v === '*') return true;
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(v);
    if (!m) return false;
    const a = +m[1], b = m[2] ? +m[2] : a;
    return a >= 1 && b <= 65535 && a <= b;
  };

  function ipToInt(ip) {
    return ip.split('.').reduce((acc, o) => (acc << 8) + (+o), 0) >>> 0;
  }

  E.ipMatch = function (rule, ip) {
    if (rule === '*') return true;
    if (rule.indexOf('/') === -1) return rule === ip;
    const [base, bits] = rule.split('/');
    const b = +bits;
    const mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
    return (ipToInt(base) & mask) === (ipToInt(ip) & mask);
  };

  E.portMatch = function (rule, port) {
    port = +port;
    if (rule === '*') return true;
    if (rule.indexOf('-') === -1) return +rule === port;
    const [a, b] = rule.split('-').map(Number);
    return port >= a && port <= b;
  };

  E.protoMatch = function (rule, proto) {
    return rule === 'ANY' || !proto || rule === proto;
  };

  E.ruleMatches = function (rule, pkt) {
    return E.ipMatch(rule.ip, pkt.ip) && E.portMatch(rule.port, pkt.port) && E.protoMatch(rule.proto, pkt.proto);
  };

  /* Urutan evaluasi:
   * 1. Blacklist IP            -> BLOCK
   * 2. Aturan BLOCK aktif      -> BLOCK
   * 3. Aturan ALLOW aktif      -> ALLOW
   * 4. Tidak ada yang cocok    -> BLOCK (default deny / allow-list)
   */
  E.evaluate = function (pkt, state) {
    const bl = (state.blacklist || []).find(b => E.ipMatch(b.ip, pkt.ip));
    if (bl) return { action: 'block', reason: 'blacklist', rule: null, blacklist: bl };

    const active = (state.rules || []).filter(r => r.active);
    const blockRule = active.find(r => r.action === 'block' && E.ruleMatches(r, pkt));
    if (blockRule) return { action: 'block', reason: 'rule', rule: blockRule };

    const allowRule = active.find(r => r.action === 'allow' && E.ruleMatches(r, pkt));
    if (allowRule) return { action: 'allow', reason: 'rule', rule: allowRule };

    return { action: 'block', reason: 'default', rule: null };
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = E;
  else root.CyberShieldEngine = E;
})(typeof window !== 'undefined' ? window : this);
