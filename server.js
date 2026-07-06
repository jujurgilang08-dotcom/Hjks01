/**
 * Key License Server — Dark WebView Edition
 * - Admin login
 * - Generate / manage license keys
 * - Device ID whitelist per key (Java app kirim device_id saat verifikasi)
 * - Backup / import (in-memory storage)
 */

const express = require("express");
const session = require("express-session");
const crypto  = require("crypto");

const app = express();

// ── ENV ──────────────────────────────────────────────────
const ADMIN_USER     = process.env.ADMIN_USER     || "admin";
const ADMIN_PASS     = process.env.ADMIN_PASS     || "admin";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const PORT           = process.env.PORT           || 3000;

// ── IN-MEMORY DB ─────────────────────────────────────────
// Key entry:
// {
//   key, createdAt, expiresAt, note, active,
//   lastUsedAt, usedCount,
//   allowedDevices: string[],   // kosong = semua device boleh
//   registeredDevices: string[] // device yang pernah pakai key ini
// }
let KEYS = {};

// ── MIDDLEWARE ────────────────────────────────────────────
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8, httpOnly: true }
}));

function requireAuth(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect("/login");
}
function requireAuthApi(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.status(401).json({ status: "error", message: "Unauthorized" });
}

// ── HELPERS ───────────────────────────────────────────────
function generateRandomKey() {
  const chars   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const segment = () => Array.from({ length: 4 }, () =>
    chars.charAt(crypto.randomInt(0, chars.length))).join("");
  return `${segment()}-${segment()}-${segment()}-${segment()}`;
}
function isExpired(e) {
  return e.expiresAt ? new Date(e.expiresAt).getTime() < Date.now() : false;
}

// ── LOGIN ─────────────────────────────────────────────────
app.get("/login", (req, res) => {
  if (req.session?.isAdmin) return res.redirect("/");
  res.send(renderLoginPage());
});
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.redirect("/");
  }
  res.send(renderLoginPage("Username atau password salah."));
});
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// ── DASHBOARD ─────────────────────────────────────────────
app.get("/", requireAuth, (req, res) => res.send(renderDashboard()));

// ── API: LIST KEYS ────────────────────────────────────────
app.get("/api/keys", requireAuthApi, (req, res) => {
  const list = Object.values(KEYS).sort((a, b) =>
    new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ status: "ok", total: list.length, keys: list });
});

// ── API: GENERATE KEY ─────────────────────────────────────
app.post("/api/keys/generate", requireAuthApi, (req, res) => {
  const { customKey, expiresAt, note, allowedDevices } = req.body;
  let keyValue = (customKey || "").trim().toUpperCase();
  if (!keyValue) {
    do { keyValue = generateRandomKey(); } while (KEYS[keyValue]);
  } else if (KEYS[keyValue]) {
    return res.status(400).json({ status: "error", message: "Key custom ini sudah ada." });
  }

  // allowedDevices bisa array atau string dipisah koma/newline
  let devices = [];
  if (allowedDevices) {
    if (Array.isArray(allowedDevices)) {
      devices = allowedDevices.map(d => d.trim()).filter(Boolean);
    } else {
      devices = allowedDevices.split(/[\n,]+/).map(d => d.trim()).filter(Boolean);
    }
  }

  const parsedExpires = (expiresAt && expiresAt !== "null" && expiresAt !== "")
    ? new Date(expiresAt).toISOString() : null;

  KEYS[keyValue] = {
    key: keyValue,
    createdAt: new Date().toISOString(),
    expiresAt: parsedExpires,
    note: note || "",
    active: true,
    lastUsedAt: null,
    usedCount: 0,
    allowedDevices: devices,
    registeredDevices: []
  };
  res.json({ status: "ok", message: "Key berhasil dibuat.", data: KEYS[keyValue] });
});

// ── API: UPDATE ALLOWED DEVICES ───────────────────────────
app.post("/api/keys/:key/devices", requireAuthApi, (req, res) => {
  const entry = KEYS[req.params.key.toUpperCase()];
  if (!entry) return res.status(404).json({ status: "error", message: "Key tidak ditemukan." });
  const { allowedDevices } = req.body;
  let devices = [];
  if (allowedDevices) {
    if (Array.isArray(allowedDevices)) {
      devices = allowedDevices.map(d => d.trim()).filter(Boolean);
    } else {
      devices = allowedDevices.split(/[\n,]+/).map(d => d.trim()).filter(Boolean);
    }
  }
  entry.allowedDevices = devices;
  res.json({ status: "ok", data: entry });
});

// ── API: TOGGLE AKTIF ─────────────────────────────────────
app.post("/api/keys/:key/toggle", requireAuthApi, (req, res) => {
  const entry = KEYS[req.params.key.toUpperCase()];
  if (!entry) return res.status(404).json({ status: "error", message: "Key tidak ditemukan." });
  entry.active = !entry.active;
  res.json({ status: "ok", data: entry });
});

// ── API: HAPUS KEY ────────────────────────────────────────
app.delete("/api/keys/:key", requireAuthApi, (req, res) => {
  const k = req.params.key.toUpperCase();
  if (!KEYS[k]) return res.status(404).json({ status: "error", message: "Key tidak ditemukan." });
  delete KEYS[k];
  res.json({ status: "ok", message: "Key dihapus." });
});

// ── API: BACKUP ───────────────────────────────────────────
app.get("/api/backup", requireAuthApi, (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="backup-${Date.now()}.json"`);
  res.send(JSON.stringify({ exportedAt: new Date().toISOString(), totalKeys: Object.keys(KEYS).length, keys: KEYS }, null, 2));
});

// ── API: IMPORT ───────────────────────────────────────────
app.post("/api/import", requireAuthApi, (req, res) => {
  try {
    const raw = req.body?.backupJson;
    if (!raw) return res.status(400).json({ status: "error", message: "File backup tidak ditemukan." });
    const parsed = JSON.parse(raw);
    if (!parsed.keys || typeof parsed.keys !== "object")
      return res.status(400).json({ status: "error", message: "Format backup tidak valid." });
    const mode = req.body.mode === "replace" ? "replace" : "merge";
    KEYS = mode === "replace" ? { ...parsed.keys } : { ...KEYS, ...parsed.keys };
    // Pastikan field device ada di semua entry
    Object.values(KEYS).forEach(e => {
      if (!e.allowedDevices) e.allowedDevices = [];
      if (!e.registeredDevices) e.registeredDevices = [];
    });
    res.json({ status: "ok", message: `Import berhasil (${mode}).`, totalKeys: Object.keys(KEYS).length });
  } catch (err) {
    res.status(400).json({ status: "error", message: "Gagal parse file: " + err.message });
  }
});

// ── API PUBLIK: VERIFY KEY ────────────────────────────────
// Java app kirim: GET /api/verify?key=XXXX&device_id=YYYY
//             atau POST /api/verify  body: { key, device_id }
// Jika allowedDevices kosong → semua device boleh, tapi device_id tetap direkam.
// Jika allowedDevices ada isi → device_id HARUS ada di list tersebut.
function handleVerify(req, res) {
  const raw       = req.method === "GET" ? req.query : req.body;
  const key       = ((raw.key       || "").toString().trim().toUpperCase());
  const deviceId  = ((raw.device_id || raw.deviceId || "").toString().trim());

  if (!key) return res.status(400).json({ status: "invalid", message: "Parameter 'key' wajib diisi.", key: null });

  const entry = KEYS[key];
  if (!entry) return res.status(404).json({ status: "invalid", message: "Key tidak ditemukan.", key });
  if (!entry.active) return res.status(403).json({ status: "inactive", message: "Key dinonaktifkan.", key });
  if (isExpired(entry)) return res.status(403).json({ status: "expired", message: "Key sudah kedaluwarsa.", key, expiresAt: entry.expiresAt });

  // Cek device ID
  if (entry.allowedDevices.length > 0) {
    if (!deviceId) return res.status(403).json({ status: "device_required", message: "Device ID wajib dikirim untuk key ini.", key });
    if (!entry.allowedDevices.includes(deviceId))
      return res.status(403).json({ status: "device_blocked", message: "Device ID tidak diizinkan.", key, deviceId });
  }

  // Rekam device
  if (deviceId && !entry.registeredDevices.includes(deviceId)) {
    entry.registeredDevices.push(deviceId);
  }

  entry.lastUsedAt = new Date().toISOString();
  entry.usedCount += 1;

  const remainingDays = entry.expiresAt
    ? Math.ceil((new Date(entry.expiresAt).getTime() - Date.now()) / 86400000)
    : null;

  return res.json({ status: "valid", message: "OK", key, createdAt: entry.createdAt, expiresAt: entry.expiresAt, remainingDays, usedCount: entry.usedCount });
}

app.get("/api/verify",  handleVerify);
app.post("/api/verify", handleVerify);

// ── HEALTH ────────────────────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ═══════════════════════════════════════════════════════════
// HTML TEMPLATES
// ═══════════════════════════════════════════════════════════

function renderLoginPage(errorMsg = "") {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"/>
<title>Login — Key Server</title>
<style>
:root{--bg:#0d0f14;--bg2:#161b25;--border:#252d3d;--text:#e2e8f0;--muted:#64748b;--accent:#3b82f6;--accent2:#2563eb;--red:#ef4444;--green:#22c55e;--yellow:#eab308;--radius:10px;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;padding:0;height:100%;background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;overflow-x:hidden}
body{display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:28px 24px;width:100%;max-width:340px;margin:20px}
.logo{font-size:28px;text-align:center;margin-bottom:6px}
h1{font-size:17px;font-weight:600;text-align:center;margin:0 0 22px;color:var(--text)}
label{font-size:12px;color:var(--muted);display:block;margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
input{width:100%;padding:11px 13px;margin-bottom:14px;background:#0d1117;border:1px solid var(--border);border-radius:7px;font-size:14px;color:var(--text);outline:none;-webkit-appearance:none}
input:focus{border-color:var(--accent)}
button{width:100%;padding:11px;background:var(--accent);color:#fff;border:none;border-radius:7px;font-size:14px;font-weight:600;cursor:pointer;-webkit-appearance:none}
button:active{background:var(--accent2)}
.error{background:#1f0707;border:1px solid #7f1d1d;color:#fca5a5;font-size:12px;padding:9px 12px;border-radius:7px;margin-bottom:14px}
</style>
</head>
<body>
<div class="box">
  <div class="logo">🔐</div>
  <h1>Key License Server</h1>
  ${errorMsg ? `<div class="error">${errorMsg}</div>` : ""}
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" required autocomplete="username" placeholder="admin"/>
    <label>Password</label>
    <input type="password" name="password" required autocomplete="current-password" placeholder="••••••••"/>
    <button type="submit">Masuk</button>
  </form>
</div>
</body>
</html>`;
}

function renderDashboard() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"/>
<title>Dashboard — Key Server</title>
<style>
:root{--bg:#0d0f14;--bg2:#161b25;--bg3:#1e2533;--border:#252d3d;--text:#e2e8f0;--muted:#64748b;--accent:#3b82f6;--accent2:#2563eb;--red:#ef4444;--green:#22c55e;--yellow:#eab308;--radius:10px;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;overflow-x:hidden;-webkit-text-size-adjust:none}

/* HEADER */
.header{background:var(--bg2);border-bottom:1px solid var(--border);padding:13px 16px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header-title{font-size:15px;font-weight:700;display:flex;align-items:center;gap:7px}
.header-title span{font-size:18px}
.btn-logout{background:transparent;border:1px solid var(--border);color:var(--muted);padding:6px 13px;border-radius:6px;font-size:12px;cursor:pointer;-webkit-appearance:none}
.btn-logout:active{background:var(--red);color:#fff;border-color:var(--red)}

/* LAYOUT */
.page{padding:14px;display:flex;flex-direction:column;gap:14px;max-width:700px;margin:0 auto}

/* CARDS */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.card-header{padding:13px 14px 0;font-size:13px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:6px}
.card-header .ico{font-size:15px}
.card-body{padding:13px 14px}

/* FORM */
label{font-size:11px;color:var(--muted);display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px;margin-top:10px}
label:first-child{margin-top:0}
input[type=text],input[type=date],select,textarea{width:100%;padding:10px 12px;background:#0d1117;border:1px solid var(--border);border-radius:7px;font-size:13px;color:var(--text);outline:none;-webkit-appearance:none;font-family:var(--font)}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:vertical;min-height:64px;font-size:12px}
select option{background:var(--bg2)}

/* BUTTONS */
.btn{padding:10px 16px;border:none;border-radius:7px;font-size:13px;font-weight:600;cursor:pointer;-webkit-appearance:none;display:inline-flex;align-items:center;gap:5px;white-space:nowrap}
.btn:active{opacity:.8}
.btn-primary{background:var(--accent);color:#fff}
.btn-green{background:#16a34a;color:#fff}
.btn-red{background:var(--red);color:#fff}
.btn-gray{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.btn-sm{padding:6px 11px;font-size:11px;border-radius:5px}
.btn-full{width:100%;justify-content:center;margin-top:12px}

/* BADGE */
.badge{padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.b-active{background:#052e16;color:var(--green);border:1px solid #14532d}
.b-inactive{background:#1f0707;color:#fca5a5;border:1px solid #7f1d1d}
.b-expired{background:#1c1007;color:#fcd34d;border:1px solid #78350f}

/* TABLE → CARDS on mobile */
.key-list{display:flex;flex-direction:column;gap:8px;margin-top:10px}
.key-card{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:11px 12px}
.key-top{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.key-mono{font-family:'SF Mono',Consolas,monospace;font-size:12px;font-weight:700;color:#93c5fd;word-break:break-all}
.key-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;font-size:11px;color:var(--muted)}
.key-meta span{display:flex;align-items:center;gap:3px}
.key-actions{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
.key-note{font-size:11px;color:var(--muted);margin-top:4px;font-style:italic}
.key-devices{font-size:10px;color:var(--muted);margin-top:4px;word-break:break-all}

/* EMPTY */
.empty{text-align:center;padding:28px;color:var(--muted);font-size:13px}

/* ENDPOINT BOX */
.code-box{background:#070b10;border:1px solid var(--border);border-radius:7px;padding:12px;font-family:'SF Mono',Consolas,monospace;font-size:11px;color:#94a3b8;overflow-x:auto;margin-top:8px;white-space:pre}

/* TOAST */
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1e2533;border:1px solid var(--border);color:var(--text);padding:10px 18px;border-radius:8px;font-size:12px;opacity:0;transition:.25s;pointer-events:none;z-index:999;white-space:nowrap;max-width:90vw;text-align:center}
.toast.show{opacity:1}

/* IMPORT ROW */
.import-row{display:flex;flex-direction:column;gap:8px;margin-top:10px}
.file-label{display:flex;align-items:center;gap:8px;background:#0d1117;border:1px solid var(--border);border-radius:7px;padding:9px 12px;cursor:pointer;font-size:12px;color:var(--muted)}
.file-label input[type=file]{display:none}
#fileChosen{font-size:11px;color:var(--muted)}

/* DEVICE MODAL */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;display:none;align-items:flex-end;justify-content:center}
.overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:14px 14px 0 0;padding:20px 16px 30px;width:100%;max-width:480px;max-height:70vh;overflow-y:auto}
.modal h3{font-size:14px;font-weight:700;margin-bottom:14px}
.modal-close{float:right;background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;line-height:1}
</style>
</head>
<body>

<div class="header">
  <div class="header-title"><span>🔑</span> Key License Server</div>
  <form method="POST" action="/logout" style="margin:0">
    <button type="submit" class="btn-logout">Logout</button>
  </form>
</div>

<div class="page">

  <!-- GENERATE KEY -->
  <div class="card">
    <div class="card-header"><span class="ico">➕</span> Generate Key Baru</div>
    <div class="card-body">
      <label>Custom Key (kosongkan = random)</label>
      <input id="customKey" type="text" placeholder="Contoh: VIP-2026-XXXX"/>
      <label>Tanggal Expired (kosongkan = tanpa batas)</label>
      <input id="expiresAt" type="date"/>
      <label>Catatan (opsional)</label>
      <input id="note" type="text" placeholder="Untuk siapa key ini?"/>
      <label>Device ID yang Diizinkan (opsional, satu per baris)</label>
      <textarea id="allowedDevices" placeholder="Kosongkan = semua device boleh&#10;Isi = hanya device ini yang bisa pakai"></textarea>
      <button class="btn btn-primary btn-full" onclick="generateKey()">⚡ Buat Key</button>
    </div>
  </div>

  <!-- DAFTAR KEY -->
  <div class="card">
    <div class="card-header"><span class="ico">📋</span> Daftar Key &nbsp;<span id="totalCount" style="color:var(--muted);font-weight:400;font-size:12px">(0)</span></div>
    <div class="card-body" style="padding-top:4px">
      <div id="keyList" class="key-list">
        <div class="empty">Loading...</div>
      </div>
    </div>
  </div>

  <!-- BACKUP & IMPORT -->
  <div class="card">
    <div class="card-header"><span class="ico">💾</span> Backup & Import</div>
    <div class="card-body">
      <p style="font-size:11px;color:var(--muted);margin-bottom:10px">Data disimpan di memori server. Backup rutin sebelum redeploy Railway.</p>
      <a href="/api/backup"><button class="btn btn-green btn-full">⬇ Download Backup</button></a>
      <div class="import-row">
        <label class="file-label">
          📂 Pilih File Backup
          <input type="file" id="importFile" accept="application/json" onchange="fileChosen(this)"/>
        </label>
        <span id="fileChosen" style="font-size:11px;color:var(--muted)">Belum ada file dipilih</span>
        <select id="importMode" style="margin-top:0">
          <option value="merge">Gabung (merge)</option>
          <option value="replace">Timpa semua (replace)</option>
        </select>
        <button class="btn btn-gray" onclick="importBackup()">⬆ Import Backup</button>
      </div>
    </div>
  </div>

  <!-- API ENDPOINT -->
  <div class="card">
    <div class="card-header"><span class="ico">🔌</span> API Endpoint</div>
    <div class="card-body">
      <p style="font-size:11px;color:var(--muted)">Kirim dari aplikasi Java untuk verifikasi key + device ID:</p>
      <div class="code-box" id="endpointBox">GET  {origin}/api/verify?key=XXXX&device_id=DEVICE
POST {origin}/api/verify
Body: { "key": "XXXX", "device_id": "DEVICE" }</div>
      <p style="font-size:11px;color:var(--muted);margin-top:10px">Response valid:</p>
      <div class="code-box">{"status":"valid","key":"...","remainingDays":12}</div>
      <p style="font-size:11px;color:var(--muted);margin-top:10px">Status device blocked:</p>
      <div class="code-box">{"status":"device_blocked","message":"Device ID tidak diizinkan."}</div>
    </div>
  </div>

</div>

<!-- DEVICE MODAL -->
<div class="overlay" id="deviceOverlay" onclick="closeDeviceModal(event)">
  <div class="modal" id="deviceModal">
    <button class="modal-close" onclick="closeDeviceModal()">×</button>
    <h3>🔒 Kelola Device ID</h3>
    <p style="font-size:11px;color:var(--muted);margin-bottom:10px">Key: <strong id="modalKey" style="color:#93c5fd"></strong></p>
    <label>Device ID yang Diizinkan (satu per baris)</label>
    <textarea id="modalDevices" style="height:100px;margin-top:6px" placeholder="Kosongkan = semua device boleh&#10;Isi = hanya device ini yang bisa pakai"></textarea>
    <p id="registeredTitle" style="font-size:11px;color:var(--muted);margin-top:10px"></p>
    <div id="registeredList" style="font-size:11px;color:#93c5fd;word-break:break-all;margin-top:4px;line-height:1.8"></div>
    <button class="btn btn-primary btn-full" style="margin-top:14px" onclick="saveDevices()">Simpan</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let currentModalKey = null;

// set endpoint box
document.getElementById('endpointBox').textContent =
  'GET  ' + window.location.origin + '/api/verify?key=XXXX&device_id=DEVICE\\n' +
  'POST ' + window.location.origin + '/api/verify\\n' +
  'Body: { "key": "XXXX", "device_id": "DEVICE" }';

function showToast(msg, dur=3000) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._t);
  t._t = setTimeout(() => t.classList.remove('show'), dur);
}

function fileChosen(el) {
  document.getElementById('fileChosen').textContent =
    el.files.length ? el.files[0].name : 'Belum ada file dipilih';
}

async function fetchKeys() {
  try {
    const res  = await fetch('/api/keys');
    const data = await res.json();
    document.getElementById('totalCount').textContent = '(' + data.total + ')';
    const list = document.getElementById('keyList');
    if (!data.keys.length) {
      list.innerHTML = '<div class="empty">Belum ada key. Buat di atas.</div>';
      return;
    }
    list.innerHTML = data.keys.map(k => {
      const now = Date.now();
      let badge = '<span class="badge b-active">Aktif</span>';
      if (!k.active) badge = '<span class="badge b-inactive">Nonaktif</span>';
      else if (k.expiresAt && new Date(k.expiresAt).getTime() < now)
        badge = '<span class="badge b-expired">Expired</span>';

      const exp  = k.expiresAt ? new Date(k.expiresAt).toLocaleDateString('id-ID') : '∞';
      const used = k.usedCount + 'x';
      const note = k.note ? '<div class="key-note">' + esc(k.note) + '</div>' : '';
      const devCount = (k.allowedDevices||[]).length;
      const devLabel = devCount > 0
        ? '<div class="key-devices">🔒 ' + devCount + ' device diizinkan' + (k.registeredDevices?.length ? ' · ' + k.registeredDevices.length + ' terdaftar' : '') + '</div>'
        : '<div class="key-devices" style="color:#4b5563">🌐 Semua device boleh</div>';

      return \`<div class="key-card">
  <div class="key-top">
    <span class="key-mono">\${esc(k.key)}</span>
    \${badge}
  </div>
  <div class="key-meta">
    <span>📅 \${new Date(k.createdAt).toLocaleDateString('id-ID')}</span>
    <span>⏰ Exp: \${exp}</span>
    <span>🔄 \${used}</span>
    \${k.lastUsedAt ? '<span>🕐 ' + new Date(k.lastUsedAt).toLocaleString('id-ID') + '</span>' : ''}
  </div>
  \${note}
  \${devLabel}
  <div class="key-actions">
    <button class="btn btn-gray btn-sm" onclick="openDeviceModal('\${esc(k.key)}', \${JSON.stringify(k.allowedDevices||[])}, \${JSON.stringify(k.registeredDevices||[])})">🔒 Device</button>
    <button class="btn btn-gray btn-sm" onclick="toggleKey('\${esc(k.key)}')">\${k.active ? 'Nonaktifkan' : 'Aktifkan'}</button>
    <button class="btn btn-red btn-sm" onclick="deleteKey('\${esc(k.key)}')">Hapus</button>
  </div>
</div>\`;
    }).join('');
  } catch(e) { console.error(e); }
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

async function generateKey() {
  const customKey      = document.getElementById('customKey').value.trim();
  const expiresAtRaw   = document.getElementById('expiresAt').value;
  const note           = document.getElementById('note').value.trim();
  const allowedDevices = document.getElementById('allowedDevices').value;
  const expiresAt = expiresAtRaw ? new Date(expiresAtRaw + 'T23:59:59').toISOString() : '';
  const res = await fetch('/api/keys/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ customKey, expiresAt: expiresAt || null, note, allowedDevices })
  });
  // tambah try-catch agar error network terlihat
  let data;
  try { data = await res.json(); } catch(e) { showToast('❌ Gagal konek ke server'); return; }
  if (data.status === 'ok') {
    showToast('✅ Key dibuat: ' + data.data.key);
    document.getElementById('customKey').value = '';
    document.getElementById('expiresAt').value = '';
    document.getElementById('note').value = '';
    document.getElementById('allowedDevices').value = '';
    fetchKeys();
  } else {
    showToast('❌ ' + (data.message || 'Gagal buat key'));
  }
}

async function toggleKey(key) {
  const res  = await fetch('/api/keys/' + encodeURIComponent(key) + '/toggle', { method:'POST' });
  const data = await res.json();
  if (data.status === 'ok') { showToast('Status diubah.'); fetchKeys(); }
}

async function deleteKey(key) {
  if (!confirm('Hapus key ' + key + '?')) return;
  const res  = await fetch('/api/keys/' + encodeURIComponent(key), { method:'DELETE' });
  const data = await res.json();
  if (data.status === 'ok') { showToast('🗑 Key dihapus.'); fetchKeys(); }
}

async function importBackup() {
  const fileInput = document.getElementById('importFile');
  const mode      = document.getElementById('importMode').value;
  if (!fileInput.files.length) { showToast('Pilih file backup.json dulu.'); return; }
  const reader = new FileReader();
  reader.onload = async (e) => {
    const res  = await fetch('/api/import', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ backupJson: e.target.result, mode })
    });
    const data = await res.json();
    if (data.status === 'ok') {
      showToast('✅ ' + data.message + ' Total: ' + data.totalKeys);
      fileInput.value = '';
      document.getElementById('fileChosen').textContent = 'Belum ada file dipilih';
      fetchKeys();
    } else {
      showToast('❌ ' + data.message);
    }
  };
  reader.readAsText(fileInput.files[0]);
}

function openDeviceModal(key, allowed, registered) {
  currentModalKey = key;
  document.getElementById('modalKey').textContent = key;
  document.getElementById('modalDevices').value = allowed.join('\\n');
  const regTitle = document.getElementById('registeredTitle');
  const regList  = document.getElementById('registeredList');
  if (registered.length) {
    regTitle.textContent = 'Device yang pernah menggunakan key ini:';
    regList.innerHTML = registered.map(d => '• ' + esc(d)).join('<br>');
  } else {
    regTitle.textContent = 'Belum ada device yang menggunakan key ini.';
    regList.innerHTML = '';
  }
  document.getElementById('deviceOverlay').classList.add('open');
}

function closeDeviceModal(e) {
  if (!e || e.target === document.getElementById('deviceOverlay'))
    document.getElementById('deviceOverlay').classList.remove('open');
}

async function saveDevices() {
  if (!currentModalKey) return;
  const allowedDevices = document.getElementById('modalDevices').value;
  const res  = await fetch('/api/keys/' + encodeURIComponent(currentModalKey) + '/devices', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ allowedDevices })
  });
  const data = await res.json();
  if (data.status === 'ok') {
    showToast('✅ Device list disimpan.');
    document.getElementById('deviceOverlay').classList.remove('open');
    fetchKeys();
  } else {
    showToast('❌ ' + data.message);
  }
}

fetchKeys();
setInterval(fetchKeys, 15000);
</script>
</body>
</html>`;
}

// ── START ─────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Key server running on port ${PORT}`));
