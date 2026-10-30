# CyberShield - Firewall Engine & Network Threat Prevention

Aplikasi web untuk memantau aktivitas jaringan, mengelola aturan firewall, dan mensimulasikan serangan jaringan. Data bersifat simulasi.

## Struktur Berkas

| Berkas | Fungsi |
|---|---|
| `index.html` | Antarmuka (5 halaman: Dashboard, Aturan Firewall, Simulasi, Log, Blacklist) |
| `style.css` | Tema gelap profesional |
| `engine.js` | Mesin firewall: validasi IP/port, pencocokan CIDR, evaluasi aturan |
| `app.js` | Logika UI, simulasi traffic/serangan, penyimpanan `localStorage` |
| `database.sql` | Skema MySQL: `firewall_rules`, `security_logs`, `blacklist_ips` + data awal |
| `test.js` | Pengujian otomatis (26 kasus) - `node test.js` |
| `HASIL_PENGUJIAN.md` | Keluaran pengujian otomatis |

## Cara Menjalankan

1. Ekstrak folder, lalu buka `index.html` di browser (Chrome/Edge/Firefox). Tidak perlu server.
2. Data aturan, log, dan blacklist tersimpan di `localStorage` browser. Untuk reset, jalankan `CyberShieldReset()` di konsol browser.
3. (Opsional) Impor skema database: `mysql -u root -p < database.sql`. Skema ini siap dipakai bila aplikasi dikembangkan dengan backend PHP; versi saat ini memakai `localStorage` sehingga PHP/MySQL tidak wajib.

## Logika Firewall (urutan evaluasi)

1. IP ada di **Blacklist** -> BLOKIR
2. Cocok dengan aturan **BLOKIR** aktif -> BLOKIR
3. Cocok dengan aturan **IZINKAN** aktif -> IZINKAN
4. Tidak ada yang cocok -> BLOKIR (*default deny*, mode allow-list)
5. IDS/IPS (hanya untuk koneksi yang lolos): signature serangan (mis. SQL Injection) atau lebih dari 12 koneksi/10 detik dari satu IP (rate limit) -> BLOKIR; IP pelanggar otomatis masuk blacklist.

Format aturan: IP `*`, `10.0.0.5`, atau CIDR `10.0.0.0/24`; port `*`, `80`, atau rentang `1000-2000`; protokol TCP/UDP/ANY.

## Pemetaan Fitur

| Kebutuhan | Lokasi |
|---|---|
| Dashboard: total paket, koneksi diizinkan, ancaman diblokir, aturan aktif | Halaman Dashboard |
| Tambah aturan, tentukan IP/port izinkan/blokir, aktif/nonaktif | Halaman Aturan Firewall |
| Simulasi traffic, tombol serangan, status diizinkan/diblokir | Halaman Simulasi Traffic & Serangan |
| Log: waktu, IP sumber, port tujuan, jenis aktivitas, tindakan | Halaman Log Keamanan |
| Daftar, tambah, hapus blacklist | Halaman Blacklist IP & Ancaman |

## Pengujian

### A. Pengujian otomatis
`node test.js` -> **26/26 lulus** (lihat `HASIL_PENGUJIAN.md`).

### B. Pengujian manual di browser (isi kolom "Hasil" dan lampirkan screenshot)

| No | Skenario | Langkah | Hasil yang diharapkan | Hasil | Screenshot |
|---|---|---|---|---|---|
| 1 | Koneksi diizinkan | Simulasi > Uji Koneksi: `203.0.113.10`, port `443`, TCP | KONEKSI DIIZINKAN, cocok aturan "Izinkan HTTPS" | | `ss-01-diizinkan.png` |
| 2 | Koneksi diblokir (aturan) | Uji `203.0.113.10`, port `23` | KONEKSI DIBLOKIR, aturan "Blokir Telnet" | | `ss-02-blokir-aturan.png` |
| 3 | Koneksi diblokir (default deny) | Uji `203.0.113.10`, port `3389` | DIBLOKIR, default deny | | `ss-03-default-deny.png` |
| 4 | Blacklist | Uji `185.220.101.45`, port `443` | DIBLOKIR, IP di Blacklist | | `ss-04-blacklist.png` |
| 5 | Pencatatan log | Buka Log Keamanan setelah uji 1-4 | 4 entri baru dengan waktu, IP, port, aktivitas, tindakan benar | | `ss-05-log.png` |
| 6 | Aktifkan aturan | Aturan Firewall: aktifkan "Izinkan SSH Admin (LAN)", uji `192.168.1.20`:`22` | DIIZINKAN; kartu "Aturan Aktif" naik jadi 5 | | `ss-06-aktifkan-aturan.png` |
| 7 | Tambah aturan | Tambah aturan BLOKIR `203.0.113.0/24`, port `*`, ANY; uji `203.0.113.10`:`443` | DIBLOKIR (BLOKIR menang atas IZINKAN) | | `ss-07-tambah-aturan.png` |
| 8 | Validasi input | Tambah aturan dengan IP `300.1.1.1` | Pesan error, aturan tidak tersimpan | | `ss-08-validasi.png` |
| 9 | Simulasi serangan | Klik Port Scan, Brute Force SSH, SQL Injection | Koneksi DIBLOKIR muncul di tabel langsung, dashboard & grafik port bertambah | | `ss-09-serangan.png` |
| 10 | DDoS & auto-blacklist | Klik DDoS / SYN Flood | Sebagian koneksi DIBLOKIR "IDS rate limit"; IP bot masuk Blacklist otomatis | | `ss-10-ddos.png` |
| 11 | Tambah/hapus blacklist | Blacklist: tambah `198.51.100.0/24`, uji `198.51.100.5`:`443` (diblokir); hapus, uji lagi (diizinkan) | Sesuai | | `ss-11-blacklist-crud.png` |
| 12 | Matikan firewall | Klik "Matikan Firewall", uji port `3389` | DIIZINKAN; status NONAKTIF, ancaman KRITIS | | `ss-12-firewall-off.png` |
| 13 | Persistensi | Muat ulang halaman | Aturan, log, blacklist tetap ada | | `ss-13-persisten.png` |

### Daftar screenshot yang disarankan untuk laporan
Dashboard, Aturan Firewall (sebelum/sesudah tambah), Simulasi (hasil uji diizinkan & diblokir), Log Keamanan, Blacklist, dan hasil `node test.js`.
