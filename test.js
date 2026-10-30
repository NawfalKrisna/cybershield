/* Pengujian otomatis mesin firewall CyberShield
 * Jalankan: node test.js
 */
const E = require('./engine.js');

const state = {
  rules: [
    { id: 1, name: 'Izinkan HTTP', action: 'allow', ip: '*', port: '80', proto: 'TCP', active: true },
    { id: 2, name: 'Izinkan HTTPS', action: 'allow', ip: '*', port: '443', proto: 'TCP', active: true },
    { id: 3, name: 'Izinkan DNS', action: 'allow', ip: '*', port: '53', proto: 'UDP', active: true },
    { id: 4, name: 'Blokir Telnet', action: 'block', ip: '*', port: '23', proto: 'TCP', active: true },
    { id: 5, name: 'Izinkan SSH Admin (LAN)', action: 'allow', ip: '192.168.1.0/24', port: '22', proto: 'TCP', active: false }
  ],
  blacklist: [{ id: 1, ip: '185.220.101.45', reason: 'TOR' }]
};
const clone = o => JSON.parse(JSON.stringify(o));
const results = [];
function t(group, name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  results.push({ group, name, expected, actual, ok });
}
const ev = (s, ip, port, proto = 'TCP') => { const r = E.evaluate({ ip, port, proto }, s); return r.action + ':' + r.reason; };

// A. Koneksi diizinkan
t('Koneksi diizinkan', 'HTTPS 203.0.113.10:443 -> allow', ev(state, '203.0.113.10', 443), 'allow:rule');
t('Koneksi diizinkan', 'HTTP 198.51.100.5:80 -> allow', ev(state, '198.51.100.5', 80), 'allow:rule');
t('Koneksi diizinkan', 'DNS UDP :53 -> allow', ev(state, '8.8.8.8', 53, 'UDP'), 'allow:rule');

// B. Koneksi diblokir
t('Koneksi diblokir', 'Telnet :23 -> block (aturan)', ev(state, '203.0.113.10', 23), 'block:rule');
t('Koneksi diblokir', 'Port tanpa aturan :3389 -> block (default deny)', ev(state, '203.0.113.10', 3389), 'block:default');
t('Koneksi diblokir', 'IP blacklist ke port 443 -> block', ev(state, '185.220.101.45', 443), 'block:blacklist');
t('Koneksi diblokir', 'DNS lewat TCP :53 -> block (protokol tidak cocok)', ev(state, '8.8.8.8', 53, 'TCP'), 'block:default');
t('Koneksi diblokir', 'SSH :22 saat aturan SSH nonaktif -> block', ev(state, '192.168.1.20', 22), 'block:default');

// C. Aktif/nonaktif aturan
const s2 = clone(state); s2.rules[4].active = true;
t('Aktif/nonaktif aturan', 'SSH LAN 192.168.1.20:22 setelah aturan diaktifkan -> allow', ev(s2, '192.168.1.20', 22), 'allow:rule');
t('Aktif/nonaktif aturan', 'SSH dari luar LAN 203.0.113.9:22 -> tetap block', ev(s2, '203.0.113.9', 22), 'block:default');
const s3 = clone(state); s3.rules[0].active = false;
t('Aktif/nonaktif aturan', 'HTTP :80 setelah aturan dinonaktifkan -> block', ev(s3, '203.0.113.10', 80), 'block:default');

// D. Tambah aturan & prioritas
const s4 = clone(state); s4.rules.push({ id: 6, name: 'Blokir subnet', action: 'block', ip: '203.0.113.0/24', port: '*', proto: 'ANY', active: true });
t('Tambah aturan & prioritas', 'Aturan BLOCK menang atas ALLOW (203.0.113.10:443)', ev(s4, '203.0.113.10', 443), 'block:rule');
t('Tambah aturan & prioritas', 'IP di luar subnet tetap allow (198.51.100.5:443)', ev(s4, '198.51.100.5', 443), 'allow:rule');
const s5 = clone(state); s5.rules.push({ id: 7, name: 'Rentang port', action: 'allow', ip: '*', port: '8000-8100', proto: 'TCP', active: true });
t('Tambah aturan & prioritas', 'Rentang port 8000-8100: :8080 -> allow', ev(s5, '1.2.3.4', 8080), 'allow:rule');
t('Tambah aturan & prioritas', 'Rentang port 8000-8100: :8101 -> block', ev(s5, '1.2.3.4', 8101), 'block:default');

// E. Blacklist tambah/hapus
const s6 = clone(state); s6.blacklist.push({ id: 2, ip: '198.51.100.0/24' });
t('Blacklist', 'CIDR 198.51.100.0/24 memblokir 198.51.100.5:443', ev(s6, '198.51.100.5', 443), 'block:blacklist');
s6.blacklist = s6.blacklist.filter(b => b.id !== 2);
t('Blacklist', 'Setelah IP dihapus dari blacklist -> allow lagi', ev(s6, '198.51.100.5', 443), 'allow:rule');

// F. Validasi input
t('Validasi input', 'IP 256.1.1.1 tidak valid', E.isValidIP('256.1.1.1'), false);
t('Validasi input', 'IP 10.0.0.5 valid', E.isValidIP('10.0.0.5'), true);
t('Validasi input', 'CIDR 10.0.0.0/33 tidak valid', E.isValidIPRule('10.0.0.0/33'), false);
t('Validasi input', 'CIDR 10.0.0.0/24 valid', E.isValidIPRule('10.0.0.0/24'), true);
t('Validasi input', 'Port 0 tidak valid', E.isValidPort('0'), false);
t('Validasi input', 'Port 65536 tidak valid', E.isValidPort('65536'), false);
t('Validasi input', 'Rentang 2000-1000 tidak valid', E.isValidPort('2000-1000'), false);
t('Validasi input', 'Port 443 valid', E.isValidPort('443'), true);
t('Validasi input', 'Rentang 1000-2000 valid', E.isValidPort('1000-2000'), true);

// Output
let md = '# Hasil Pengujian Otomatis CyberShield\n\n| # | Kelompok | Kasus Uji | Diharapkan | Hasil | Status |\n|---|---|---|---|---|---|\n';
results.forEach((r, i) => {
  md += `| ${i + 1} | ${r.group} | ${r.name} | \`${JSON.stringify(r.expected)}\` | \`${JSON.stringify(r.actual)}\` | ${r.ok ? 'LULUS' : 'GAGAL'} |\n`;
});
const pass = results.filter(r => r.ok).length;
md += `\n**Ringkasan: ${pass}/${results.length} kasus uji lulus.**\n`;
console.log(md);
process.exit(pass === results.length ? 0 : 1);
