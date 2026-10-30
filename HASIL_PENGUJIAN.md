# Hasil Pengujian Otomatis CyberShield

| # | Kelompok | Kasus Uji | Diharapkan | Hasil | Status |
|---|---|---|---|---|---|
| 1 | Koneksi diizinkan | HTTPS 203.0.113.10:443 -> allow | `"allow:rule"` | `"allow:rule"` | LULUS |
| 2 | Koneksi diizinkan | HTTP 198.51.100.5:80 -> allow | `"allow:rule"` | `"allow:rule"` | LULUS |
| 3 | Koneksi diizinkan | DNS UDP :53 -> allow | `"allow:rule"` | `"allow:rule"` | LULUS |
| 4 | Koneksi diblokir | Telnet :23 -> block (aturan) | `"block:rule"` | `"block:rule"` | LULUS |
| 5 | Koneksi diblokir | Port tanpa aturan :3389 -> block (default deny) | `"block:default"` | `"block:default"` | LULUS |
| 6 | Koneksi diblokir | IP blacklist ke port 443 -> block | `"block:blacklist"` | `"block:blacklist"` | LULUS |
| 7 | Koneksi diblokir | DNS lewat TCP :53 -> block (protokol tidak cocok) | `"block:default"` | `"block:default"` | LULUS |
| 8 | Koneksi diblokir | SSH :22 saat aturan SSH nonaktif -> block | `"block:default"` | `"block:default"` | LULUS |
| 9 | Aktif/nonaktif aturan | SSH LAN 192.168.1.20:22 setelah aturan diaktifkan -> allow | `"allow:rule"` | `"allow:rule"` | LULUS |
| 10 | Aktif/nonaktif aturan | SSH dari luar LAN 203.0.113.9:22 -> tetap block | `"block:default"` | `"block:default"` | LULUS |
| 11 | Aktif/nonaktif aturan | HTTP :80 setelah aturan dinonaktifkan -> block | `"block:default"` | `"block:default"` | LULUS |
| 12 | Tambah aturan & prioritas | Aturan BLOCK menang atas ALLOW (203.0.113.10:443) | `"block:rule"` | `"block:rule"` | LULUS |
| 13 | Tambah aturan & prioritas | IP di luar subnet tetap allow (198.51.100.5:443) | `"allow:rule"` | `"allow:rule"` | LULUS |
| 14 | Tambah aturan & prioritas | Rentang port 8000-8100: :8080 -> allow | `"allow:rule"` | `"allow:rule"` | LULUS |
| 15 | Tambah aturan & prioritas | Rentang port 8000-8100: :8101 -> block | `"block:default"` | `"block:default"` | LULUS |
| 16 | Blacklist | CIDR 198.51.100.0/24 memblokir 198.51.100.5:443 | `"block:blacklist"` | `"block:blacklist"` | LULUS |
| 17 | Blacklist | Setelah IP dihapus dari blacklist -> allow lagi | `"allow:rule"` | `"allow:rule"` | LULUS |
| 18 | Validasi input | IP 256.1.1.1 tidak valid | `false` | `false` | LULUS |
| 19 | Validasi input | IP 10.0.0.5 valid | `true` | `true` | LULUS |
| 20 | Validasi input | CIDR 10.0.0.0/33 tidak valid | `false` | `false` | LULUS |
| 21 | Validasi input | CIDR 10.0.0.0/24 valid | `true` | `true` | LULUS |
| 22 | Validasi input | Port 0 tidak valid | `false` | `false` | LULUS |
| 23 | Validasi input | Port 65536 tidak valid | `false` | `false` | LULUS |
| 24 | Validasi input | Rentang 2000-1000 tidak valid | `false` | `false` | LULUS |
| 25 | Validasi input | Port 443 valid | `true` | `true` | LULUS |
| 26 | Validasi input | Rentang 1000-2000 valid | `true` | `true` | LULUS |

**Ringkasan: 26/26 kasus uji lulus.**

