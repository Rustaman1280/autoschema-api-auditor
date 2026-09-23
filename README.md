# AutoSchema & API Auditor 🛡️⚡
### Autonomous Hybrid Security Engineer & Database Performance Architect
**Powered by Nebius Token Factory (NVIDIA Nemotron-3) & Tavily Threat Intelligence**

AutoSchema & API Auditor adalah sistem otonom tingkat lanjut (*end-to-end*) yang menganalisis skema database, kueri SQL, dan endpoint API untuk mendeteksi kerentanan keamanan dan bottleneck performa, memverifikasi ancaman secara *real-time* via **Tavily Search API**, serta mensintesis perbaikan siap produksi:
- **Database Migrations**: Skrip `UP` dan `DOWN` yang *non-blocking* (`CONCURRENTLY` di PostgreSQL) dan *fully reversible*.
- **Backend / API Patches**: Handler yang bersih, tahan injeksi (parameterized), memiliki proteksi BOLA/IDOR (OWASP API1:2023), dan bebas dari *N+1 query antipattern*.

---

## 🏛️ Arsitektur Hybrid Proyek

Repositori ini menggunakan arsitektur hybrid profesional dengan dua antarmuka independen yang berbagi standar dan test fixture:

```
autoschema-api-auditor/
├── cli/                         # 🐍 Engine Python untuk CI/CD, Terminal & Serverless
│   ├── agent.py                 # Autonomous ReAct agent loop (Nebius Token Factory)
│   ├── cli.py                   # Antarmuka CLI interaktif
│   ├── config.py                # Konfigurasi & loader environment
│   ├── system_prompt.py         # Master System Prompt teroptimasi
│   ├── tools.py                 # Skema OpenAI Tool & Tavily Search executor
│   ├── run_demo.py              # Runner verifikasi otomatis end-to-end
│   ├── requirements.txt         # Dependensi Python
│   └── reports/                 # Hasil audit markdown yang digenerate
├── web/                         # ⚡ Modern Web Dashboard (Next.js 14 + Tailwind CSS)
│   ├── app/                     # Next.js App Router (Dashboard & /api/audit)
│   ├── lib/                     # System prompt port, Nebius client, Tavily client, Mock data
│   ├── package.json             # Dependensi Frontend
│   └── .env.example             # Konfigurasi frontend
├── sample_inputs/               # 🧪 Shared Test Fixtures (Akses universal CLI & Web)
│   ├── ecommerce_schema.sql     # Skema database bermasalah (unindexed FK, plaintext secrets, missing RLS)
│   └── order_controller.ts      # Controller API rentan (SQL injection, BOLA/IDOR, loop N+1)
├── .env.example                 # Konfigurasi root
└── LICENSE                      # Lisensi MIT
```

---

## 🚀 Panduan Memulai Cepat (Quickstart)

### 1. Menjalankan Web Dashboard (Next.js 14 + Tailwind CSS)
Antarmuka web modern dirancang khusus untuk demonstrasi juri hackathon dengan dukungan *Smart Simulation Mode* (fallback instan zero-failure) dan *Live Nebius Cloud*:

```bash
cd web
npm install
npm run dev
```
Buka browser di **`http://localhost:3000`**.

Fitur Dashboard:
- **Dark Mode UI** dengan visual stepper progres 3-tahap (*Static Triage* $\rightarrow$ *Tavily Threat Research* $\rightarrow$ *Nemotron Patch Generation*).
- **Dual-Tab Input**: DDL/SQL Database vs Controller API (TypeScript/Python).
- **One-Click Samples**: Tombol muat cepat untuk `ecommerce_schema.sql` dan `order_controller.ts`.
- **Export**: Salin kode markdown atau unduh laporan `.md` langsung.

---

### 2. Menjalankan Python Engine (CLI & Terminal)
Engine Python dirancang dengan **zero mandatory dependencies** (menggunakan Python Standard Library) untuk integrasi CI/CD:

```bash
cd cli

# Menjalankan verifikasi demo otomatis
python run_demo.py

# Mengaudit berkas skema secara langsung
python cli.py audit --file ../sample_inputs/ecommerce_schema.sql

# Mengaudit controller API dan menyimpan output kustom
python cli.py audit --file ../sample_inputs/order_controller.ts --output ../reports/custom_audit.md

# Menampilkan Master System Prompt aktif
python cli.py prompt
```

---

## ⚙️ Konfigurasi Environment (Nebius & Tavily)

Untuk menghubungkan ke **Nebius Token Factory** dan **Tavily Search API**:

1. Salin `.env.example` ke `.env`:
   ```bash
   cp .env.example .env
   ```

2. Isi API key Anda:
   ```ini
   # Nebius AI Token Factory (https://tokenfactory.nebius.ai)
   NEBIUS_API_KEY=your_nebius_api_key_here
   NEBIUS_BASE_URL=https://api.tokenfactory.nebius.ai/v1

   # Tavily Search API (https://tavily.com)
   TAVILY_API_KEY=your_tavily_api_key_here
   ```

> **Catatan Hackathon**: Jika API key tidak diisi, baik CLI maupun Web App secara otomatis beroperasi dalam **Smart Simulation Mode** menggunakan cache ancaman dan hasil audit terverifikasi, sehingga demonstrasi juri dijamin 100% andal tanpa risiko crash/500 error.

---

## 🔍 Hasil Verifikasi Masalah & Remediasi

| Komponen | Masalah yang Dideteksi | Standar / Kerentanan | Remediasi yang Dihasilkan |
|---|---|---|---|
| **`ecommerce_schema.sql`** | Plaintext password & credit card storage | **CWE-312**, **PCI-DSS 3.4** | Hashing Argon2id/Bcrypt & tokenisasi gateway |
| | Foreign keys tanpa index (`orders.user_id`, dll.) | **PostgreSQL Concurrency** | Migrasi `CREATE INDEX CONCURRENTLY` non-blocking |
| | JSONB metadata tanpa GIN index | **PG Chapter 8.14** | Indeks `USING gin (metadata jsonb_path_ops)` |
| | Multi-tenancy tanpa isolasi | **OWASP A01:2021 (Broken Access Control)** | Row-Level Security (RLS) policies & tenant wrapper |
| **`order_controller.ts`** | String concatenation dalam SQL query | **CWE-89 (SQL Injection)** | Strict parameterized query bindings (`$1`, `$2`) |
| | Tidak ada validasi kepemilikan tenant/user | **OWASP API1:2023 (BOLA / IDOR)** | Filter konteks tenant langsung pada level kueri |
| | Pengulangan kueri dalam loop `for` | **N+1 Query Antipattern** | *Single query aggregation* via PostgreSQL `json_agg` (O(N) $\rightarrow$ O(1)) |

---

## 📜 Lisensi
Proyek ini didistribusikan di bawah lisensi [MIT](file:///C:/rustaman/autoschema-api-auditor/LICENSE).
