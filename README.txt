# 🔐 Security System Dashboard

Dashboard keamanan lengkap dengan pemantauan CCTV real-time, MFA, audit logging, enkripsi data, secret management, deteksi anomali perilaku, File Integrity Monitoring (FIM) dengan pop-up, dan terminal sistem.

## ✨ Fitur

| Fitur | Deskripsi |
|-------|-----------|
| 📹 **CCTV Monitoring** | Pemantauan kamera real-time (RTSP/HTTP wireless), grid multi-kamera, status online/offline via **ping sungguhan** ke IP kamera |
| 🌙 **Night Vision** | Mode penglihatan malam per kamera (filter citra) |
| 🔍 **Zoom Kamera** | Perbesar/perkecil/reset feed kamera |
| 🎛️ **Camera Settings** | Kecerahan, kontras, kualitas grafis per kamera |
| 📤 **Share Kamera** | Bagikan tautan langsung ke kamera tertentu |
| 📻 **Walkie Talkie** | Komunikasi push-to-talk per kamera |
| ⏺️ **Rekaman CCTV** | Rekam, simpan, putar, dan unduh rekaman |
| 🔑 **MFA (TOTP)** | Autentikasi dua faktor dengan kode 6 digit dari aplikasi autentikator |
| 📜 **Audit Logging** | Pencatatan semua aktivitas dengan timestamp, user, IP, dan level |
| 🔒 **Enkripsi Data** | AES-256-GCM untuk secret vault, bcrypt untuk password hashing |
| 🗝️ **Secret Management** | Vault secret terenkripsi, generate/rotasi/lihat/hapus secret |
| 🧠 **Deteksi Anomali** | Analisis perilaku, deteksi login mencurigakan, IP anomali, pola tidak normal |
| 📁 **FIM + Pop-up** | Pemantauan integritas file, alert pop-up saat file diubah |
| 🖥️ **Terminal** | Terminal interaktif untuk status sistem, log, dan perintah |
| 🌐 **Dua Bahasa** | Indonesia & English (bisa diubah di pengaturan) |
| 📝 **Update Details** | Riwayat dan detail pembaruan aplikasi |

## 🛠️ Teknologi

- **Backend**: Node.js (Express + WebSocket) & PHP (alternatif)
- **Frontend**: HTML, CSS, JavaScript
- **Keamanan**: bcryptjs, jsonwebtoken, crypto (AES-256-GCM)
- **Data**: JSON files (data/)

## 🚀 Cara Menjalankan

### Opsi 1: Node.js (Direkomendasikan)
```bash
# Install dependencies
npm install

# Jalankan server
node server.js
```
Buka **http://localhost:3000**

### Opsi 2: PHP (Alternatif)
```bash
# Jalankan PHP API server
php -S localhost:8000 -t api/
```

## 🔑 Login Default

| Username | Password |
|----------|----------|
| `admin` | `S3cure@2024!Admin` |

> **Catatan**: Ubah password default setelah login pertama!

## 📁 Struktur Proyek

```
project security sistem v2/
├── server.js          → Backend Node.js (Express + WebSocket)
├── package.json       → Dependencies
├── api/index.php      → Backend PHP alternatif
├── public/
│   ├── index.html     → Dashboard utama
│   ├── css/style.css  → Styling
│   └── js/            → Modul JavaScript
│       ├── app.js     → Logika utama
│       ├── cctv.js    → CCTV monitoring
│       ├── mfa.js     → MFA TOTP
│       ├── audit.js   → Audit logging
│       ├── anomaly.js → Deteksi anomali
│       ├── fim.js     → FIM + pop-up
│       ├── secrets.js → Secret management
│       ├── terminal.js→ Terminal
│       └── i18n.js    → Internasionalisasi
├── data/
│   ├── users.json     → Data user
│   ├── secrets.json   → Secret vault (terenkripsi)
│   ├── audit.log      → Audit log
│   └── fim.db         → FIM baseline
└── README.md
```

## 🔧 Perintah Terminal

| Perintah | Fungsi |
|----------|--------|
| `help` | Menampilkan perintah |
| `status` | Status sistem |
| `cctv` | Status kamera CCTV |
| `secrets` | Daftar secret |
| `audit` | Log audit terbaru |
| `fim` | Pemeriksaan integritas file |
| `anomalies` | Anomali terdeteksi |
| `ping <host>` | Ping target (real) |
| `security` | Ringkasan keamanan |
| `clear` | Bersihkan terminal |

## 📡 API Endpoints

| Method | Endpoint | Fungsi |
|--------|----------|--------|
| POST | `/api/auth/login` | Login |
| POST | `/api/mfa/setup` | Setup MFA |
| POST | `/api/mfa/verify` | Verifikasi MFA |
| GET | `/api/secrets` | Daftar secret |
| POST | `/api/secrets` | Tambah secret |
| GET | `/api/fim/check` | Cek integritas file |
| GET | `/api/audit` | Log audit |
| GET | `/api/anomalies` | Anomali |
| GET | `/api/cctv` | Status CCTV (real ping) |
| GET | `/api/ping?host=` | Ping host (real) |
| GET | `/api/system/status` | Status sistem |

## ⚠️ Catatan Keamanan

- Data disimpan dalam file JSON di folder `data/`
- Secret dienkripsi dengan **AES-256-GCM**
- Password di-hash dengan **bcrypt**
- Untuk produksi, ganti `JWT_SECRET` dan `ENCRYPTION_KEY` di `server.js`
- Di Vercel, `JWT_SECRET` otomatis di-fallback ke `data/secret.key` jika env var tidak di-set (agar login tetap berfungsi). Untuk keamanan maksimal, set env var `JWT_SECRET` di dashboard Vercel.
- Gunakan HTTPS untuk koneksi aman

## 📄 Lisensi

MIT
