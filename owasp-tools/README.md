# OWASP Rekon Aman

Tool recon aman untuk domain yang sudah kamu punya izin cek. Output-nya `report.html` dan `report.json`.

Fitur:

- Validator scope dari `scope.txt`
- Record DNS
- WHOIS
- Status HTTP dan redirect
- Header keamanan
- Info sertifikat TLS
- Flag cookie
- `robots.txt`, `sitemap.xml`, dan file publik umum
- Deteksi form dan parameter tanpa payload
- Fingerprint teknologi ringan
- Mapping OWASP Top 10 dengan catatan validasi manual
- HTML report standalone yang bisa langsung dibuka

## Cara Jalan dari Web GitHub Pages

Project ini sudah punya dashboard web di:

```text
docs/index.html
```

Setelah repository di-upload ke GitHub:

1. Buka `Settings` repo
2. Masuk `Pages`
3. Pada `Build and deployment`, pilih `Deploy from a branch`
4. Pilih branch `main`
5. Pilih folder `/docs`
6. Save
7. Buka URL GitHub Pages yang diberikan

Di dashboard:

1. Isi `Target URL / Domain`
2. Klik `Buka Actions`
3. Target otomatis dicopy ke clipboard
4. Di halaman GitHub Actions, klik `Run workflow`
5. Paste target ke input workflow
6. Klik `Run workflow`
7. Setelah selesai, download artifact report

Kenapa tidak ada token di halaman: GitHub Pages adalah static hosting, jadi halaman web tidak bisa menjalankan Python langsung. Tanpa backend/token, cara paling aman adalah membuka form resmi GitHub Actions. Autentikasinya memakai login GitHub kamu, bukan token yang ditempel di halaman.

## Cara Jalan dari Tab Actions

Setelah repository ini di-upload ke GitHub:

1. Buka tab `Actions`
2. Pilih workflow `OWASP Rekon Aman`
3. Klik `Run workflow`
4. Isi `target`, contoh:

```text
https://example.com
```

5. Opsional isi `scope_domains`, contoh:

```text
example.com,*.example.com
```

6. Klik `Run workflow`
7. Setelah job selesai, buka bagian `Artifacts`
8. Download `owasp-rekon-aman-report`
9. Buka `report.html` di browser

Catatan penting: GitHub Pages hanya bisa host file statis, jadi scan tidak bisa dijalankan langsung dari halaman HTML biasa tanpa backend. Workflow GitHub Actions dipakai sebagai mesin eksekusi.

## Cara Jalan di Windows

1. Install Python 3.11+ dari `https://www.python.org/downloads/`
2. Buka folder `owasp-safe-recon`
3. Double click `run_local_web_windows.bat`
4. Browser akan terbuka otomatis
5. Masukkan target, contoh:

```text
https://mahacorefilms.com
```

6. Klik `Jalankan Scan`
7. Buka hasil dari tombol `Buka Report HTML`

Report otomatis dibuat di folder yang sama:

- `report.html`
- `report.json`

Kebutuhan Windows:

- Python 3.11 atau lebih baru
- Internet aktif untuk install dependency pertama kali dan untuk scan target
- Saat install Python, centang `Add Python to PATH`
- Tidak perlu hosting/server publik
- Tidak perlu Node.js
- Tidak perlu Docker
- Tidak perlu database

Catatan: aplikasi membuka local web UI di `127.0.0.1`. Itu hanya berjalan di komputer sendiri, bukan server internet.

## Cara Jalan Lokal di macOS/Linux

```bash
chmod +x run_local_web_mac_linux.sh
./run_local_web_mac_linux.sh
```

## Cara Jalan Manual

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe owasp_recon.py https://example.com --scope-file scope.txt --out report.html --json-out report.json
```

Untuk macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python owasp_recon.py https://example.com --scope-file scope.txt --out report.html --json-out report.json
```

## Batas Aman

Tool ini tidak melakukan:

- brute force
- exploit
- fuzzing agresif
- payload SQLi/XSS/RCE
- SSRF request
- bypass auth
- scanning port agresif

Semua temuan yang butuh validasi ditandai sebagai review manual.
