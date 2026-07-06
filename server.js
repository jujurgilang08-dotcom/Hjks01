/**
 * Key License Server
 * ------------------------------------------------------
 * - Admin login (username/password dari ENV Railway)
 * - Generate license key (random / custom) + durasi (tanggal expired)
 * - API endpoint untuk verifikasi key (dipanggil dari aplikasi Java, dsb)
 * - Backup semua key jadi backup.json (download)
 * - Import backup.json untuk restore data (karena storage in-memory,
 *   akan reset tiap kali Railway redeploy)
 *
 * PENTING: Semua data key disimpan di MEMORY (variabel di RAM).
 * Setiap kali server restart / redeploy, data akan HILANG.
 * Gunakan fitur "Backup" secara rutin, lalu simpan file backup.json
 * di komputer kamu. Setelah redeploy, gunakan fitur "Import" untuk
 * memulihkan semua key yang sudah pernah dibuat.
 *
 * UI: Dark theme, dioptimasi untuk tampilan WebView browser Android
 * (viewport mobile-first, area sentuh besar, aman untuk notch/safe-area,
 * tanpa hover-only interaction, font system Android).
 */

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();

// ------------------------------------------------------
// KONFIGURASI DARI ENVIRONMENT VARIABLE (set di Railway)
// ------------------------------------------------------
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin";
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const PORT = process.env.PORT || 3000;

// ------------------------------------------------------
// "DATABASE" IN-MEMORY
// Struktur tiap key:
// {
//   key: "XXXX-XXXX-XXXX-XXXX",
//   createdAt: ISOString,
//   expiresAt: ISOString | null,   // null = tanpa batas waktu
//   note: "keterangan opsional",
//   active: true/false,            // bisa dinonaktifkan manual
//   lastUsedAt: ISOString | null,
//   usedCount: number
// }
// ------------------------------------------------------
let KEYS = {}; // key string -> object di atas

// ------------------------------------------------------
// MIDDLEWARE
// ------------------------------------------------------
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 8, // 8 jam
      httpOnly: true,
    },
  })
);

function requireAuth(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect("/login");
}

function requireAuthApi(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).json({ status: "error", message: "Unauthorized" });
}

// ------------------------------------------------------
// HELPER
// ------------------------------------------------------
function generateRandomKey() {
  // Format: XXXX-XXXX-XXXX-XXXX (huruf besar + angka)
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // tanpa karakter ambigu
  const segment = () =>
    Array.from({ length: 4 }, () =>
      chars.charAt(crypto.randomInt(0, chars.length))
    ).join("");
  return `${segment()}-${segment()}-${segment()}-${segment()}`;
}

function isExpired(entry) {
  if (!entry.expiresAt) return false;
  return new Date(entry.expiresAt).getTime() < Date.now();
}

// ------------------------------------------------------
// HALAMAN LOGIN
// ------------------------------------------------------
app.get("/login", (req, res) => {
  if (req.session && req.session.isAdmin) return res.redirect("/");
  res.send(renderLoginPage());
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.redirect("/");
  }
  return res.send(renderLoginPage("Username atau password salah."));
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// ------------------------------------------------------
// HALAMAN DASHBOARD ADMIN
// ------------------------------------------------------
app.get("/", requireAuth, (req, res) => {
  res.send(renderDashboard());
});

// ------------------------------------------------------
// API: LIST KEY (untuk tabel dashboard)
// ------------------------------------------------------
app.get("/api/keys", requireAuthApi, (req, res) => {
  const list = Object.values(KEYS).sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  );
  res.json({ status: "ok", total: list.length, keys: list });
});

// ------------------------------------------------------
// API: GENERATE KEY BARU
// body: { customKey?: string, expiresAt?: string (ISO date), note?: string }
// ------------------------------------------------------
app.post("/api/keys/generate", requireAuthApi, (req, res) => {
  const { customKey, expiresAt, note } = req.body;

  let keyValue = (customKey || "").trim().toUpperCase();
  if (!keyValue) {
    // generate sampai dapat yang belum dipakai
    do {
      keyValue = generateRandomKey();
    } while (KEYS[keyValue]);
  } else if (KEYS[keyValue]) {
    return res
      .status(400)
      .json({ status: "error", message: "Key custom ini sudah ada." });
  }

  const entry = {
    key: keyValue,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
    note: note || "",
    active: true,
    lastUsedAt: null,
    usedCount: 0,
  };

  KEYS[keyValue] = entry;
  res.json({ status: "ok", message: "Key berhasil dibuat.", data: entry });
});

// ------------------------------------------------------
// API: TOGGLE AKTIF / NONAKTIF KEY
// ------------------------------------------------------
app.post("/api/keys/:key/toggle", requireAuthApi, (req, res) => {
  const entry = KEYS[req.params.key.toUpperCase()];
  if (!entry)
    return res.status(404).json({ status: "error", message: "Key tidak ditemukan." });
  entry.active = !entry.active;
  res.json({ status: "ok", data: entry });
});

// ------------------------------------------------------
// API: HAPUS KEY
// ------------------------------------------------------
app.delete("/api/keys/:key", requireAuthApi, (req, res) => {
  const k = req.params.key.toUpperCase();
  if (!KEYS[k])
    return res.status(404).json({ status: "error", message: "Key tidak ditemukan." });
  delete KEYS[k];
  res.json({ status: "ok", message: "Key dihapus." });
});

// ------------------------------------------------------
// API: BACKUP (download semua data jadi backup.json)
// ------------------------------------------------------
app.get("/api/backup", requireAuthApi, (req, res) => {
  const payload = {
    exportedAt: new Date().toISOString(),
    totalKeys: Object.keys(KEYS).length,
    keys: KEYS,
  };
  res.setHeader("Content-Type", "application/json");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="backup-${Date.now()}.json"`
  );
  res.send(JSON.stringify(payload, null, 2));
});

// ------------------------------------------------------
// API: IMPORT (upload backup.json untuk restore)
// Body JSON: { backupJson: "<isi file backup.json sebagai string>", mode: "merge"|"replace" }
// File dibaca di sisi browser (FileReader), lalu dikirim sebagai teks JSON biasa
// — tidak perlu multipart/form-data, jadi tanpa dependency tambahan (multer).
//
// mode: "merge" (default, gabung tanpa menghapus yang sudah ada)
//       "replace" (timpa semua data yang ada sekarang)
// ------------------------------------------------------
app.post("/api/import", requireAuthApi, (req, res) => {
  try {
    const raw = req.body && req.body.backupJson;
    if (!raw) {
      return res
        .status(400)
        .json({ status: "error", message: "Isi file backup tidak ditemukan." });
    }

    const parsed = JSON.parse(raw);
    if (!parsed.keys || typeof parsed.keys !== "object") {
      return res
        .status(400)
        .json({ status: "error", message: "Format backup.json tidak valid." });
    }

    const mode = req.body.mode === "replace" ? "replace" : "merge";
    if (mode === "replace") {
      KEYS = { ...parsed.keys };
    } else {
      KEYS = { ...KEYS, ...parsed.keys };
    }

    res.json({
      status: "ok",
      message: `Import berhasil (mode: ${mode}).`,
      totalKeys: Object.keys(KEYS).length,
    });
  } catch (err) {
    res
      .status(400)
      .json({ status: "error", message: "Gagal membaca file: " + err.message });
  }
});

// ------------------------------------------------------
// API PUBLIK: VERIFIKASI KEY (dipanggil dari aplikasi Java / client lain)
// method: GET atau POST
// param: key  (query string ?key=XXXX atau body JSON { "key": "XXXX" })
//
// Response JSON detail:
// {
//   status: "valid" | "invalid" | "expired" | "inactive",
//   message: "...",
//   key: "XXXX-XXXX-XXXX-XXXX",
//   createdAt: "...",
//   expiresAt: "..." | null,
//   remainingDays: number | null
// }
// ------------------------------------------------------
function handleVerify(req, res) {
  const key = ((req.method === "GET" ? req.query.key : req.body.key) || "")
    .toString()
    .trim()
    .toUpperCase();

  if (!key) {
    return res.status(400).json({
      status: "invalid",
      message: "Parameter 'key' wajib diisi.",
      key: null,
    });
  }

  const entry = KEYS[key];
  if (!entry) {
    return res.status(404).json({
      status: "invalid",
      message: "Key tidak ditemukan.",
      key,
    });
  }

  if (!entry.active) {
    return res.status(403).json({
      status: "inactive",
      message: "Key dinonaktifkan oleh admin.",
      key,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
    });
  }

  if (isExpired(entry)) {
    return res.status(403).json({
      status: "expired",
      message: "Key sudah kedaluwarsa.",
      key,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
    });
  }

  // valid -> update statistik pemakaian
  entry.lastUsedAt = new Date().toISOString();
  entry.usedCount += 1;

  let remainingDays = null;
  if (entry.expiresAt) {
    remainingDays = Math.ceil(
      (new Date(entry.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
    );
  }

  return res.json({
    status: "valid",
    message: "OK",
    key,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    remainingDays,
    usedCount: entry.usedCount,
  });
}

app.get("/api/verify", handleVerify);
app.post("/api/verify", handleVerify);

// ------------------------------------------------------
// HEALTH CHECK (berguna untuk Railway)
// ------------------------------------------------------
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ------------------------------------------------------
// TEMPLATE HTML — LOGIN PAGE (Dark Theme, mobile/WebView-first)
// ------------------------------------------------------
function renderLoginPage(errorMsg) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, viewport-fit=cover" />
<meta name="theme-color" content="#0b0d12" />
<meta name="color-scheme" content="dark" />
<title>Login Admin - Key Server</title>
<style>
  :root {
    --bg: #0b0d12;
    --bg-elevated: #12151c;
    --surface: #171b24;
    --surface-2: #1e232e;
    --border: #262c38;
    --text: #e8eaee;
    --text-muted: #8b93a3;
    --accent: #5b8cff;
    --accent-strong: #4674ee;
    --danger: #ff6b6b;
    --danger-bg: rgba(255, 107, 107, 0.12);
    --radius: 14px;
    --safe-top: env(safe-area-inset-top, 0px);
    --safe-bottom: env(safe-area-inset-bottom, 0px);
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body {
    height: 100%;
    overscroll-behavior-y: contain;
  }
  body {
    margin: 0;
    font-family: Roboto, "Segoe UI", -apple-system, system-ui, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: calc(24px + var(--safe-top)) 20px calc(24px + var(--safe-bottom));
  }
  .box {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 28px 24px;
    border-radius: var(--radius);
    box-shadow: 0 8px 30px rgba(0,0,0,0.45);
    width: 100%;
    max-width: 360px;
  }
  .lock-badge {
    width: 52px; height: 52px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    font-size: 24px;
    margin: 0 auto 16px;
  }
  h1 {
    font-size: 19px; margin: 0 0 4px; color: var(--text);
    text-align: center; font-weight: 600;
  }
  .sub {
    text-align: center; color: var(--text-muted); font-size: 13px;
    margin: 0 0 22px;
  }
  label {
    font-size: 13px; color: var(--text-muted); display: block;
    margin-bottom: 6px; font-weight: 500;
  }
  input {
    width: 100%;
    padding: 13px 14px;
    margin-bottom: 16px;
    border: 1px solid var(--border);
    background: var(--bg-elevated);
    color: var(--text);
    border-radius: 10px;
    font-size: 16px; /* >=16px agar Android WebView tidak auto-zoom saat fokus */
    outline: none;
    transition: border-color 0.15s ease;
  }
  input:focus {
    border-color: var(--accent);
  }
  input::placeholder { color: #565f70; }
  button {
    width: 100%;
    padding: 14px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    -webkit-appearance: none;
  }
  button:active { background: var(--accent-strong); transform: scale(0.99); }
  .error {
    color: var(--danger);
    background: var(--danger-bg);
    border: 1px solid rgba(255,107,107,0.25);
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 13px;
    margin-bottom: 16px;
  }
</style>
</head>
<body>
  <div class="box">
    <div class="lock-badge">🔐</div>
    <h1>Login Admin</h1>
    <p class="sub">Key License Server</p>
    ${errorMsg ? `<div class="error">${errorMsg}</div>` : ""}
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" required autocomplete="username" autocapitalize="off" autocorrect="off" />
      <label>Password</label>
      <input type="password" name="password" required autocomplete="current-password" />
      <button type="submit">Masuk</button>
    </form>
  </div>
</body>
</html>`;
}

// ------------------------------------------------------
// TEMPLATE HTML — DASHBOARD ADMIN (Dark Theme, mobile/WebView-first)
// ------------------------------------------------------
function renderDashboard() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, viewport-fit=cover" />
<meta name="theme-color" content="#0b0d12" />
<meta name="color-scheme" content="dark" />
<title>Key Server - Dashboard</title>
<style>
  :root {
    --bg: #0b0d12;
    --bg-elevated: #12151c;
    --surface: #171b24;
    --surface-2: #1e232e;
    --border: #262c38;
    --text: #e8eaee;
    --text-muted: #8b93a3;
    --text-faint: #565f70;
    --accent: #5b8cff;
    --accent-strong: #4674ee;
    --green: #34d399;
    --green-bg: rgba(52, 211, 153, 0.12);
    --red: #ff6b6b;
    --red-bg: rgba(255, 107, 107, 0.12);
    --amber: #fbbf24;
    --amber-bg: rgba(251, 191, 36, 0.12);
    --radius: 14px;
    --safe-top: env(safe-area-inset-top, 0px);
    --safe-bottom: env(safe-area-inset-bottom, 0px);
    --safe-left: env(safe-area-inset-left, 0px);
    --safe-right: env(safe-area-inset-right, 0px);
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body {
    background: var(--bg);
    overscroll-behavior-y: contain;
  }
  body {
    margin: 0;
    font-family: Roboto, "Segoe UI", -apple-system, system-ui, Arial, sans-serif;
    color: var(--text);
    padding-bottom: calc(24px + var(--safe-bottom));
    -webkit-font-smoothing: antialiased;
  }
  header {
    background: var(--bg-elevated);
    padding: calc(14px + var(--safe-top)) calc(16px + var(--safe-right)) 14px calc(16px + var(--safe-left));
    display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 10;
  }
  header h1 { font-size: 16px; margin: 0; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  header form { margin: 0; }
  header button {
    background: var(--surface-2); color: var(--red); border: 1px solid var(--border);
    padding: 9px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500;
  }
  header button:active { background: var(--red-bg); }

  .container {
    max-width: 720px;
    margin: 0 auto;
    padding: 16px calc(14px + var(--safe-right)) 8px calc(14px + var(--safe-left));
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 16px;
    margin-bottom: 16px;
  }
  .card h2 {
    font-size: 14px; margin: 0 0 14px; color: var(--text);
    font-weight: 600; display: flex; align-items: center; gap: 8px;
  }
  .row { display: flex; flex-direction: column; gap: 12px; margin-bottom: 14px; }
  label { font-size: 12.5px; color: var(--text-muted); display: block; margin-bottom: 6px; font-weight: 500; }
  input, select {
    width: 100%;
    padding: 12px 13px;
    border: 1px solid var(--border);
    background: var(--bg-elevated);
    color: var(--text);
    border-radius: 9px;
    font-size: 16px; /* mencegah auto-zoom di Android WebView saat fokus input */
  }
  input::placeholder { color: var(--text-faint); }
  input:focus, select:focus { outline: none; border-color: var(--accent); }

  .btn {
    padding: 12px 18px; border: none; border-radius: 9px; font-size: 14px; font-weight: 600;
    cursor: pointer; color: #fff; -webkit-appearance: none; width: 100%;
  }
  .btn-primary { background: var(--accent); }
  .btn-primary:active { background: var(--accent-strong); }
  .btn-green { background: #16a34a; }
  .btn-green:active { background: #15803d; }
  .btn-gray { background: var(--surface-2); color: var(--text); border: 1px solid var(--border); }
  .btn-gray:active { background: #262c38; }
  .btn-red { background: var(--red-bg); color: var(--red); border: 1px solid rgba(255,107,107,0.25); }
  .btn-red:active { background: rgba(255,107,107,0.2); }
  .btn-small { padding: 8px 12px; font-size: 12.5px; width: auto; }

  /* Tabel: scroll horizontal di layar sempit, header sticky untuk kenyamanan mobile */
  .table-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); -webkit-overflow-scrolling: touch; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; min-width: 640px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  th { color: var(--text-muted); font-weight: 600; background: var(--surface-2); font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.03em; }
  tr:last-child td { border-bottom: none; }
  tr:active td { background: var(--surface-2); }

  .badge { padding: 4px 9px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .badge-active { background: var(--green-bg); color: var(--green); }
  .badge-inactive { background: var(--red-bg); color: var(--red); }
  .badge-expired { background: var(--amber-bg); color: var(--amber); }

  .actions { display: flex; gap: 6px; }
  .muted { color: var(--text-muted); font-size: 12.5px; line-height: 1.5; }
  .key-mono { font-family: "SF Mono", "Roboto Mono", Consolas, monospace; font-weight: 600; letter-spacing: 0.02em; }

  .empty-state {
    text-align: center; padding: 28px 16px; color: var(--text-muted); font-size: 13px;
  }

  .toast {
    position: fixed;
    left: 16px; right: 16px;
    bottom: calc(20px + var(--safe-bottom));
    background: var(--surface-2);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 13px 16px;
    border-radius: 10px;
    font-size: 13.5px;
    opacity: 0;
    transform: translateY(8px);
    transition: opacity 0.25s ease, transform 0.25s ease;
    pointer-events: none;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    z-index: 50;
  }
  .toast.show { opacity: 1; transform: translateY(0); }

  .import-box { display: flex; flex-direction: column; gap: 10px; }
  .import-row { display: flex; gap: 10px; }
  .import-row select { flex: 1; }

  input[type="file"] {
    padding: 10px;
    font-size: 13px;
    color: var(--text-muted);
  }

  .endpoint-box {
    background: #05070a;
    color: #b7c4e0;
    padding: 13px 14px;
    border-radius: 9px;
    font-family: "SF Mono", "Roboto Mono", Consolas, monospace;
    font-size: 12px;
    overflow-x: auto;
    margin-top: 8px;
    border: 1px solid var(--border);
    white-space: pre;
    -webkit-overflow-scrolling: touch;
  }
  .endpoint-box code { color: #7dd3fc; }

  @media (min-width: 480px) {
    .row { flex-direction: row; flex-wrap: wrap; }
    .row > div { flex: 1; min-width: 150px; }
    .btn { width: auto; }
    .import-row { flex-wrap: nowrap; }
  }
</style>
</head>
<body>
<header>
  <h1>🔑 Key License Server</h1>
  <form method="POST" action="/logout"><button type="submit">Logout</button></form>
</header>

<div class="container">

  <div class="card">
    <h2>➕ Generate Key Baru</h2>
    <div class="row">
      <div>
        <label>Custom Key (kosongkan untuk random)</label>
        <input id="customKey" type="text" placeholder="Contoh: VIP-2026-XXXX" autocapitalize="characters" autocorrect="off" />
      </div>
      <div>
        <label>Tanggal Expired (kosongkan = tanpa batas)</label>
        <input id="expiresAt" type="date" />
      </div>
      <div>
        <label>Catatan (opsional)</label>
        <input id="note" type="text" placeholder="Untuk siapa key ini?" />
      </div>
    </div>
    <button class="btn btn-primary" onclick="generateKey()">Buat Key</button>
  </div>

  <div class="card">
    <h2>📋 Daftar Key (<span id="totalCount">0</span>)</h2>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Key</th>
          <th>Status</th>
          <th>Dibuat</th>
          <th>Expired</th>
          <th>Dipakai</th>
          <th>Catatan</th>
          <th>Aksi</th>
        </tr>
      </thead>
      <tbody id="keyTableBody"></tbody>
    </table>
    </div>
    <div id="emptyState" class="empty-state" style="display:none;">Belum ada key. Buat key baru di atas.</div>
  </div>

  <div class="card">
    <h2>💾 Backup &amp; Import</h2>
    <p class="muted" style="margin-top:0;">
      Data key disimpan di memori server. Setiap kali Railway redeploy, data akan reset.
      Download backup secara rutin, lalu import kembali setelah redeploy.
    </p>
    <div class="import-box">
      <a href="/api/backup" style="text-decoration:none;"><button class="btn btn-green" style="width:100%;">⬇️ Download Backup (backup.json)</button></a>
      <input type="file" id="importFile" accept="application/json" />
      <div class="import-row">
        <select id="importMode">
          <option value="merge">Gabung (merge)</option>
          <option value="replace">Timpa semua (replace)</option>
        </select>
        <button class="btn btn-gray" style="flex:1;" onclick="importBackup()">⬆️ Import</button>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>🔌 API Endpoint untuk Aplikasi Java</h2>
    <p class="muted">Kirim request GET atau POST ke endpoint berikut untuk verifikasi key:</p>
    <div class="endpoint-box">GET  ${"${window.location.origin}"}/api/verify?key=XXXX-XXXX-XXXX-XXXX

POST ${"${window.location.origin}"}/api/verify
Body (JSON): { "key": "XXXX-XXXX-XXXX-XXXX" }</div>
    <p class="muted" style="margin-top:10px;">
      Response contoh saat valid:<br/>
      <code style="color:#7dd3fc;">{"status":"valid","message":"OK","key":"...","expiresAt":"...","remainingDays":12}</code>
    </p>
  </div>

</div>

<div class="toast" id="toast"></div>

<script>
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => t.classList.remove('show'), 3000);
}

async function fetchKeys() {
  const res = await fetch('/api/keys');
  const data = await res.json();
  const tbody = document.getElementById('keyTableBody');
  const emptyState = document.getElementById('emptyState');
  document.getElementById('totalCount').textContent = data.total;
  tbody.innerHTML = '';

  if (data.total === 0) {
    emptyState.style.display = 'block';
  } else {
    emptyState.style.display = 'none';
  }

  data.keys.forEach(k => {
    const now = Date.now();
    let statusHtml = '<span class="badge badge-active">Aktif</span>';
    if (!k.active) {
      statusHtml = '<span class="badge badge-inactive">Nonaktif</span>';
    } else if (k.expiresAt && new Date(k.expiresAt).getTime() < now) {
      statusHtml = '<span class="badge badge-expired">Expired</span>';
    }

    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td class="key-mono">\${k.key}</td>
      <td>\${statusHtml}</td>
      <td class="muted">\${new Date(k.createdAt).toLocaleString('id-ID')}</td>
      <td class="muted">\${k.expiresAt ? new Date(k.expiresAt).toLocaleDateString('id-ID') : '-'}</td>
      <td class="muted">\${k.usedCount}x</td>
      <td class="muted">\${k.note || '-'}</td>
      <td class="actions">
        <button class="btn btn-gray btn-small" onclick="toggleKey('\${k.key}')">\${k.active ? 'Nonaktifkan' : 'Aktifkan'}</button>
        <button class="btn btn-red btn-small" onclick="deleteKey('\${k.key}')">Hapus</button>
      </td>
    \`;
    tbody.appendChild(tr);
  });
}

async function generateKey() {
  const customKey = document.getElementById('customKey').value.trim();
  const expiresAtRaw = document.getElementById('expiresAt').value;
  const note = document.getElementById('note').value.trim();

  let expiresAt = null;
  if (expiresAtRaw) {
    // set ke akhir hari (23:59:59) pada tanggal yang dipilih
    expiresAt = new Date(expiresAtRaw + 'T23:59:59').toISOString();
  }

  const res = await fetch('/api/keys/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ customKey, expiresAt, note })
  });
  const data = await res.json();
  if (data.status === 'ok') {
    showToast('Key berhasil dibuat: ' + data.data.key);
    document.getElementById('customKey').value = '';
    document.getElementById('expiresAt').value = '';
    document.getElementById('note').value = '';
    fetchKeys();
  } else {
    showToast('Gagal: ' + data.message);
  }
}

async function toggleKey(key) {
  const res = await fetch('/api/keys/' + encodeURIComponent(key) + '/toggle', { method: 'POST' });
  const data = await res.json();
  if (data.status === 'ok') { showToast('Status key diubah.'); fetchKeys(); }
}

async function deleteKey(key) {
  if (!confirm('Yakin ingin menghapus key ' + key + '?')) return;
  const res = await fetch('/api/keys/' + encodeURIComponent(key), { method: 'DELETE' });
  const data = await res.json();
  if (data.status === 'ok') { showToast('Key dihapus.'); fetchKeys(); }
}

async function importBackup() {
  const fileInput = document.getElementById('importFile');
  const mode = document.getElementById('importMode').value;
  if (!fileInput.files.length) { showToast('Pilih file backup.json dulu.'); return; }

  const file = fileInput.files[0];
  const reader = new FileReader();
  reader.onload = async function(e) {
    const backupJson = e.target.result;
    const res = await fetch('/api/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ backupJson, mode })
    });
    const data = await res.json();
    if (data.status === 'ok') {
      showToast(data.message + ' Total key sekarang: ' + data.totalKeys);
      fileInput.value = '';
      fetchKeys();
    } else {
      showToast('Gagal import: ' + data.message);
    }
  };
  reader.onerror = function() { showToast('Gagal membaca file.'); };
  reader.readAsText(file);
}

fetchKeys();
setInterval(fetchKeys, 15000); // auto refresh tiap 15 detik
</script>
</body>
</html>`;
}

// ------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Key server berjalan di port ${PORT}`);
});
