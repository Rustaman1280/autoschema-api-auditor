# AutoSchema & API Auditor Agent 🛡️⚡

Autonomous End-to-End Database Schema & API Security/Performance Auditor.

AutoSchema & API Auditor adalah agen otonom tingkat lanjut yang bertindak sebagai *Senior Security Engineer* dan *Database Performance Architect*. Agen ini secara mandiri menganalisis skema database, kueri SQL, dan endpoint API, melakukan verifikasi ancaman/standar secara *real-time* via **Tavily Search API**, mengevaluasi dampak produksi (*blast radius*), dan menghasilkan kode remediasi siap pakai:
- **Database Migrations**: Skrip `UP` dan `DOWN` yang *non-blocking* (`CONCURRENTLY` di PostgreSQL) dan *fully reversible*.
- **Backend / API Patches**: Kode controller yang bersih, tahan injeksi (parameterized), memiliki proteksi BOLA/IDOR, dan bebas dari *N+1 query antipattern*.

---

## 🏛️ Arsitektur Alur Kerja (Workflow Loop)

```
       +-------------------------------------------------------------+
       |   Input: DDL (.sql, .prisma) atau API Controller (.ts, .py) |
       +-------------------------------------------------------------+
                                      |
                                      v
                      [ 1. Intake & Semantic Triage ]
           Kategorisasi: PERFORMANCE | SECURITY | ARCHITECTURE
                                      |
                                      v
                 [ 2. Autonomous Research & Tool Invocation ]
                 Pencarian CVE / Advisory via Tavily Search API
                   (Batas terarah: 2-3 searches per anomali)
                                      |
                                      v
                 [ 3. Blast Radius & Root-Cause Evaluation ]
             Analisis Table Locking, Algoritma O(N) vs O(log N),
                      Exfiltration Risk, Multi-Tenancy
                                      |
                                      v
                   [ 4. Production Remediation Synthesis ]
             - Safe Non-Blocking SQL Migrations (UP & DOWN)
             - Hardened API Handlers with Parameterized Queries
                                      |
                                      v
               [ Output: Structured Markdown Production Report ]
```

---

## 📁 Struktur Direktori

```
C:\rustaman\autoschema-api-auditor\
├── .env.example                 # Template konfigurasi environment
├── config.py                    # Loader konfigurasi & parameter agen
├── system_prompt.py             # Master System Prompt teroptimasi
├── tools.py                     # Skema OpenAI Tool & Tavily Search executor
├── app.py                       # Antarmuka Web Interaktif (Streamlit)
├── agent.py                     # ReAct loop engine (Nebius / OpenAI-compatible)
├── cli.py                       # Antarmuka CLI interaktif
├── run_demo.py                  # Runner verifikasi otomatis end-to-end
├── requirements.txt             # Dependensi proyek
├── sample_inputs/               # Berkas uji dengan kerentanan realistis
│   ├── ecommerce_schema.sql     # Skema SQL dengan unindexed FK, plaintext secret, missing RLS
│   └── order_controller.ts      # Controller dengan SQL Injection, BOLA, dan N+1 query
└── reports/                     # Hasil audit markdown yang dihasilkan
    ├── audit_report_ecommerce_schema.md
    └── audit_report_order_controller.md
```

---

## 🚀 Panduan Memulai Cepat (Quickstart)

Proyek ini dirancang **zero mandatory external dependencies** (menggunakan *Python Standard Library* bawaan), sehingga dapat langsung dijalankan tanpa instalasi paket pihak ketiga jika diinginkan.

### 1. Menjalankan Demo Verifikasi Seketika (Simulasi Offline)

```bash
cd C:\rustaman\autoschema-api-auditor
python run_demo.py
```

Perintah ini akan langsung mengaudit `sample_inputs/ecommerce_schema.sql` dan `sample_inputs/order_controller.ts`, lalu menyimpan laporan lengkap ke direktori `reports/`.

---

### 2. Mengaudit Berkas Kustom via CLI

```bash
# Mengaudit berkas skema SQL
python cli.py audit --file sample_inputs/ecommerce_schema.sql

# Mengaudit controller API dan menyimpan ke lokasi tertentu
python cli.py audit --file sample_inputs/order_controller.ts --output my_report.md

# Melihat Master System Prompt yang aktif
python cli.py prompt
```

---

### 3. Menjalankan Antarmuka Web (Streamlit UI)

```bash
# Menjalankan Web UI di browser
streamlit run app.py
```
Akses web UI melalui browser di `http://localhost:8501`. Web UI mendukung upload file, pemilihan mode *Live Nebius* vs *Simulation*, real-time progress tracing, dan tombol unduh laporan `.md`.

---

## ⚙️ Konfigurasi Runtime Nebius Token Factory & Tavily

Untuk menghubungkan agen ke model LLM langsung (misalnya **NVIDIA Nemotron 3** atau **Llama 3.1 70B**) dan pencarian live **Tavily API**:

1. Salin `.env.example` menjadi `.env`:
   ```bash
   cp .env.example .env
   ```

2. Isi nilai API key pada `.env`:
   ```ini
   # Nebius AI Studio Token Factory (https://studio.nebius.ai)
   NEBIUS_API_KEY=your_actual_nebius_api_key
   NEBIUS_BASE_URL=https://api.studio.nebius.ai/v1
   MODEL_NAME=nvidia/nemotron-3-super-120b-instruct

   # Tavily Search (https://tavily.com)
   TAVILY_API_KEY=tvly-your_tavily_key
   TAVILY_BASE_URL=https://api.tavily.com/search

   # Parameter Tuning
   AGENT_TEMPERATURE=0.1
   MAX_TOOL_ITERATIONS=6
   DEFAULT_DATABASE_DIALECT=PostgreSQL 16
   ```

3. Jalankan audit dalam mode live:
   ```bash
   python cli.py audit --file path/to/your/schema.sql
   ```
   Agen akan secara otomatis memanggil API Nebius, mengeksekusi `tavily_search` secara dinamis jika menemukan library/pola yang mencurigakan, dan mengembalikan laporan produksi.

---

## 🔍 Rekap Hasil Uji Verifikasi

### Test Case 1: `ecommerce_schema.sql`
- **Tingkat Risiko**: CRITICAL
- **Anomali yang Terdeteksi & Diperbaiki**:
  1. **CWE-312 & PCI-DSS 3.4**: Kolom `password` dan `credit_card_number` dalam bentuk teks polos. Diberikan migrasi ke hashing Argon2id/Bcrypt dan tokenisasi pembayaran.
  2. **PostgreSQL FK Table Locks**: Foreign keys (`orders.user_id`, `order_items.order_id`, dll.) tanpa indeks. Diberikan migrasi `CREATE INDEX CONCURRENTLY` non-blocking.
  3. **Unindexed JSONB**: Kolom `metadata` tanpa GIN index. Diberikan indeks `USING gin (metadata jsonb_path_ops)`.
  4. **Multi-Tenancy Isolation**: Diberikan penerapan Row-Level Security (RLS) PostgreSQL dan *context wrapper* sesi tenant.

### Test Case 2: `order_controller.ts`
- **Tingkat Risiko**: CRITICAL
- **Anomali yang Terdeteksi & Diperbaiki**:
  1. **CWE-89 (SQL Injection)**: Interpolasi string `${orderId}` diganti dengan *parameterized query bindings* (`$1`, `$2`).
  2. **OWASP API1:2023 (BOLA / IDOR)**: Validasi kepemilikan tenant (`tenant_id = $2`) dari sesi autentikasi pengguna.
  3. **N+1 Query Antipattern**: Pengulangan kueri di dalam loop `for` dieliminasi menjadi kueri tunggal teroptimasi dengan PostgreSQL JSON aggregation (`json_agg` + `json_build_object`). Kompleksitas jaringan turun dari **O(N)** menjadi **O(1)**.

---

## 📜 Lisensi & Standar Kepatuhan
- Mengacu pada standar **OWASP Top 10**, **OWASP API Security Top 10 (2023)**, **CWE MITRE**, dan **PostgreSQL Concurrency Guidelines**.
