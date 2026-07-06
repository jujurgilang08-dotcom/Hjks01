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
// TEMPLATE HTML — LOGIN PAGE
// ------------------------------------------------------
function renderLoginPage(errorMsg) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Login Admin - Key Server</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    background: #f4f5f7; display: flex; align-items: center; justify-content: center;
    height: 100vh;
  }
  .box {
    background: #fff; padding: 32px; border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08); width: 100%; max-width: 340px;
  }
  h1 { font-size: 20px; margin: 0 0 20px; color: #222; }
  label { font-size: 13px; color: #555; display: block; margin-bottom: 6px; }
  input {
    width: 100%; padding: 10px 12px; margin-bottom: 14px; border: 1px solid #ddd;
    border-radius: 6px; font-size: 14px;
  }
  button {
    width: 100%; padding: 10px; background: #2563eb; color: #fff; border: none;
    border-radius: 6px; font-size: 14px; cursor: pointer;
  }
  button:hover { background: #1d4ed8; }
  .error { color: #dc2626; font-size: 13px; margin-bottom: 12px; }
</style>
</head>
<body>
  <div class="box">
    <h1>🔐 Login Admin</h1>
    ${errorMsg ? `<div class="error">${errorMsg}</div>` : ""}
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" required autocomplete="username" />
      <label>Password</label>
      <input type="password" name="password" required autocomplete="current-password" />
      <button type="submit">Masuk</button>
    </form>
  </div>
</body>
</html>`;
}

// ------------------------------------------------------
// TEMPLATE HTML — DASHBOARD ADMIN
// ------------------------------------------------------
function renderDashboard() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Key Server - Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    background: #f4f5f7; color: #222;
  }
  header {
    background: #fff; padding: 16px 24px; display: flex; justify-content: space-between;
    align-items: center; border-bottom: 1px solid #e5e7eb;
  }
  header h1 { font-size: 18px; margin: 0; }
  header form { margin: 0; }
  header button {
    background: #ef4444; color: #fff; border: none; padding: 8px 14px;
    border-radius: 6px; cursor: pointer; font-size: 13px;
  }
  .container { max-width: 1000px; margin: 24px auto; padding: 0 16px; }
  .card {
    background: #fff; border-radius: 10px; padding: 20px; margin-bottom: 20px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
  }
  .card h2 { font-size: 15px; margin: 0 0 14px; color: #111; }
  .row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  .row > div { flex: 1; min-width: 160px; }
  label { font-size: 12px; color: #555; display: block; margin-bottom: 4px; }
  input, select {
    width: 100%; padding: 9px 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;
  }
  .btn {
    padding: 9px 16px; border: none; border-radius: 6px; font-size: 13px; cursor: pointer;
    color: #fff;
  }
  .btn-primary { background: #2563eb; }
  .btn-primary:hover { background: #1d4ed8; }
  .btn-green { background: #16a34a; }
  .btn-green:hover { background: #15803d; }
  .btn-gray { background: #6b7280; }
  .btn-gray:hover { background: #4b5563; }
  .btn-red { background: #dc2626; }
  .btn-red:hover { background: #b91c1c; }
  .btn-small { padding: 5px 10px; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eee; }
  th { color: #666; font-weight: 600; background: #fafafa; }
  .badge {
    padding: 3px 8px; border-radius: 20px; font-size: 11px; font-weight: 600;
  }
  .badge-active { background: #dcfce7; color: #166534; }
  .badge-inactive { background: #fee2e2; color: #991b1b; }
  .badge-expired { background: #fef3c7; color: #92400e; }
  .actions button { margin-right: 4px; }
  .muted { color: #888; font-size: 12px; }
  .toast {
    position: fixed; bottom: 20px; right: 20px; background: #111; color: #fff;
    padding: 12px 18px; border-radius: 8px; font-size: 13px; opacity: 0; transition: 0.3s;
    pointer-events: none; max-width: 320px;
  }
  .toast.show { opacity: 1; }
  .key-mono { font-family: "SF Mono", Consolas, monospace; font-weight: 600; }
  .import-box { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .endpoint-box {
    background: #0f172a; color: #e2e8f0; padding: 12px 14px; border-radius: 8px;
    font-family: monospace; font-size: 12px; overflow-x: auto; margin-top: 8px;
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
        <input id="customKey" type="text" placeholder="Contoh: VIP-2026-XXXX" />
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
    <div style="overflow-x:auto;">
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
  </div>

  <div class="card">
    <h2>💾 Backup & Import</h2>
    <p class="muted">
      Data key disimpan di memori server. Setiap kali Railway redeploy, data akan reset.
      Download backup secara rutin, lalu import kembali setelah redeploy.
    </p>
    <div class="import-box">
      <a href="/api/backup"><button class="btn btn-green">⬇️ Download Backup (backup.json)</button></a>
      <input type="file" id="importFile" accept="application/json" />
      <select id="importMode">
        <option value="merge">Gabung (merge)</option>
        <option value="replace">Timpa semua (replace)</option>
      </select>
      <button class="btn btn-gray" onclick="importBackup()">⬆️ Import Backup</button>
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
      <code>{"status":"valid","message":"OK","key":"...","expiresAt":"...","remainingDays":12}</code>
    </p>
  </div>

</div>

<div class="toast" id="toast"></div>

<script>
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

async function fetchKeys() {
  const res = await fetch('/api/keys');
  const data = await res.json();
  const tbody = document.getElementById('keyTableBody');
  document.getElementById('totalCount').textContent = data.total;
  tbody.innerHTML = '';

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
