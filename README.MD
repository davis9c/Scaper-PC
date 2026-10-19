# Manajemen Perangkat

Aplikasi web untuk mengumpulkan informasi dasar perangkat melalui link, menyimpan hasil ke SQLite, dan melihat/mengelolanya dari dashboard. Aplikasi berjalan di Docker dan menggunakan UserGate sebagai penyedia autentikasi.

## Menjalankan dengan Docker

1. Pastikan Docker Desktop dan Docker Compose sudah berjalan.
2. Salin `.env.example` menjadi `.env`, lalu isi `USERGATE_API_KEY` dengan API key UserGate yang memiliki izin untuk endpoint login.
3. Atur `APP_PUBLIC_URL` ke alamat aplikasi yang dapat dibuka oleh perangkat yang akan didata. Contoh untuk jaringan lokal: `http://192.168.1.20:8080`. Alamat `localhost` hanya dapat dibuka dari komputer yang menjalankan Docker.
4. Jalankan dari folder proyek:

   ```powershell
   docker compose up --build -d
   ```

5. Buka `APP_PUBLIC_URL` di browser. Status layanan dapat diperiksa di `/health`.

Data database disimpan pada named volume `me-data` dan tetap ada setelah container dibuat ulang. Untuk melihat log:

```powershell
docker compose logs -f me
```

Hentikan aplikasi tanpa menghapus data:

```powershell
docker compose down
```

Jangan menjalankan `docker compose down -v` kecuali memang ingin menghapus semua data aplikasi.

## Login dan aktivasi pengguna

- Login diverifikasi oleh `POST /api/v1/auth/login` UserGate sesuai spesifikasi di `plan/USERGATE_API_REFERENCE_COMPLETE.md`. Password hanya dikirim ke UserGate; aplikasi tidak menyimpan password atau token UserGate.
- Pengguna UserGate pertama yang berhasil login menjadi **superadmin lokal**.
- Login UserGate yang valid berikutnya akan membuat akun lokal berstatus **menunggu aktivasi**. Superadmin mengaktifkannya di bagian **Manajemen pengguna**.
- Akun harus aktif di UserGate dan berstatus aktif secara lokal agar dapat login.
- Pengguna lokal aktif dapat melihat hasil. Hanya superadmin yang dapat mengelola pengguna, membuat link pengumpulan, dan mencabut link.
- Menu **Manajemen lokal** hanya tampil untuk superadmin. Superadmin dapat mengubah status lokal (menunggu/aktif/nonaktif) dan peran lokal (user/superadmin) tanpa mengubah akun sumber di UserGate. Aplikasi menolak perubahan yang menonaktifkan atau menurunkan peran superadmin aktif terakhir, serta perubahan pada akun sendiri.
- Akun lokal tidak memiliki password sendiri dan tidak dapat dibuat sebagai kredensial mandiri; pengguna harus memiliki akun UserGate yang berhasil login terlebih dahulu.

API key disimpan di file `.env`, tidak di dalam image Docker. Untuk menjalankan di balik reverse proxy HTTPS, atur `APP_PUBLIC_URL` ke URL HTTPS, `TRUST_PROXY=true` hanya jika proxy tepercaya meneruskan header IP, dan `COOKIE_SECURE=true`.

## Alur pengumpulan perangkat

1. Superadmin membuat link dengan nama lokasi atau tujuan, lalu membagikannya kepada pengguna perangkat.
2. Pada Windows, pengguna membuka link dan mengunduh `me-device-collector.cmd`, lalu klik dua kali untuk mengumpulkan data. Peluncur memerlukan koneksi ke server aplikasi untuk mengambil kolektor PowerShell, menjalankannya hanya dalam proses tersebut, lalu menghapus salinan sementara. Alternatifnya, unduh `me-device-collector.ps1` dan jalankan manual. Kolektor mengirim hostname, user Windows aktif, MAC adapter jaringan aktif, port TCP yang mendengarkan, port UDP yang terikat, IP lokal, IP publik, dan platform Windows.
3. Pada perangkat non-Windows, pengguna bisa memilih pengiriman browser. Browser tidak dapat membaca hostname, user Windows, MAC address, maupun port lokal.
4. Hasil muncul di tabel dashboard. Link dapat dicabut agar tidak menerima pengiriman baru; data yang sudah tersimpan tidak dihapus.
4. Tabel mendukung pencarian di halaman aktif, pengelompokan berdasarkan link/lokasi, nama perangkat, platform, browser, IP publik, atau IP lokal, serta pagination.

Informasi browser mencakup label perangkat (opsional), platform dan browser, user-agent, bahasa, zona waktu, ukuran layar, perkiraan jumlah core/memori yang diungkapkan browser, koneksi jaringan jika tersedia, IP lokal best-effort, IP publik, dan IP yang terlihat oleh server. Kolektor PowerShell menambahkan hostname, user Windows, MAC adapter aktif, dan port TCP/UDP.

## Batasan dan privasi IP

- Browser modern membatasi akses ke informasi sistem. Halaman web tidak dapat membaca MAC address, hostname Windows, user Windows, prosesor/model grafis, port, atau inventaris hardware; gunakan skrip PowerShell yang disediakan melalui link pengumpulan.
- IP lokal dicoba melalui WebRTC. Browser atau jaringan dapat menyamarkannya, sehingga nilai ini bisa kosong.
- Untuk mendapatkan IP publik perangkat, browser meminta `https://api.ipify.org`. Layanan tersebut menerima permintaan IP perangkat. Jika tidak tersedia, kolom IP publik kosong.
- IP teramati server berasal dari koneksi yang sampai ke aplikasi. Di balik proxy, teruskan IP klien dan aktifkan `TRUST_PROXY` hanya bila proxy itu tepercaya. Di belakang NAT, alamat ini tidak selalu sama dengan IP publik.
- Link pengumpulan adalah rahasia akses bagi siapa pun yang memilikinya. Bagikan hanya kepada pihak yang berhak, dan cabut link setelah tidak dibutuhkan.
- Jalankan kolektor hanya pada perangkat yang diizinkan untuk didata. Script menjalankan perintah baca-saja untuk mengumpulkan MAC adapter aktif dan endpoint port lokal, kemudian mengirim laporan ke aplikasi melalui link rahasia.
- Halaman lama `me.html` dan `jalankan-me.ps1` tetap tersedia untuk laporan Windows lokal; file tersebut tidak mengirim data ke aplikasi Docker.

## Pengaturan

Variabel yang tersedia di `.env`:

| Variabel | Keterangan |
|---|---|
| `USERGATE_API_KEY` | Wajib. API key UserGate. |
| `USERGATE_API_BASE` | URL API UserGate; default mengacu ke dokumentasi UserGate. |
| `PORT` | Port host Docker; default `8080`. |
| `APP_PUBLIC_URL` | URL dasar yang dipakai saat membuat link pengumpulan. |
| `TRUST_PROXY` | Gunakan `true` hanya jika ada reverse proxy tepercaya. |
| `COOKIE_SECURE` | Gunakan `true` jika aplikasi diakses melalui HTTPS. |
