require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const OWNER_EMAIL = (process.env.OWNER_EMAIL || 'owner@novamessenger.app').toLowerCase();
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const uniq = Date.now() + '-' + Math.round(Math.random() * 1e9);
      cb(null, uniq + '-' + file.originalname.replace(/\s+/g, '_'));
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024 }
});

const db = new sqlite3.Database(path.join(__dirname, 'novamessenger.db'));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      verified INTEGER NOT NULL DEFAULT 0,
      verify_code_hash TEXT,
      verify_code_expires INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS dialogs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_a INTEGER NOT NULL,
      user_b INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      UNIQUE(user_a, user_b)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dialog_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      text TEXT,
      file_url TEXT,
      file_name TEXT,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);
});

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_PORT || 587) === '465',
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
});

const onlineUsers = new Map();

function sendMail(to, subject, html) {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log('[MAIL DEV]', { to, subject, html });
    return Promise.resolve();
  }
  return mailer.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    html,
  });
}

function now() { return Date.now(); }
function code6() { return String(Math.floor(100000 + Math.random() * 900000)); }
function hashCode(code) { return crypto.createHash('sha256').update(code).digest('hex'); }

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'No auth' });
  if ((req.user.email || '').toLowerCase() !== OWNER_EMAIL && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

function logAction(userId, action) {
  db.run(`INSERT INTO logs (user_id, action, created_at) VALUES (?, ?, ?)`, [userId || null, action, now()]);
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password too short' });

  const normalizedEmail = String(email).toLowerCase().trim();
  db.get(`SELECT id FROM users WHERE email = ?`, [normalizedEmail], async (err, existing) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (existing) return res.status(409).json({ error: 'Email already exists' });

    const code = code6();
    const passwordHash = await bcrypt.hash(String(password), 10);
    const expires = now() + 15 * 60 * 1000;

    db.run(
      `INSERT INTO users (name, email, password_hash, role, verified, verify_code_hash, verify_code_expires, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [String(name).trim(), normalizedEmail, passwordHash, normalizedEmail === OWNER_EMAIL ? 'admin' : 'user', 0, hashCode(code), expires, now(), now()],
      async function (insertErr) {
        if (insertErr) return res.status(500).json({ error: 'DB insert error' });

        await sendMail(
          normalizedEmail,
          'Код подтверждения NovaMessenger',
          `<div style="font-family:Arial,sans-serif;line-height:1.6"><h2>NovaMessenger</h2><p>Ваш код подтверждения:</p><div style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</div><p>Код действует 15 минут.</p></div>`
        );

        logAction(this.lastID, 'register_requested');
        res.json({ ok: true, message: 'Verification code sent' });
      }
    );
  });
});

app.post('/api/verify-email', (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'Missing fields' });
  const normalizedEmail = String(email).toLowerCase().trim();

  db.get(`SELECT * FROM users WHERE email = ?`, [normalizedEmail], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.verified) return res.status(400).json({ error: 'Already verified' });
    if (!user.verify_code_hash || !user.verify_code_expires || user.verify_code_expires < now()) {
      return res.status(400).json({ error: 'Code expired' });
    }
    if (hashCode(String(code).trim()) !== user.verify_code_hash) {
      return res.status(400).json({ error: 'Invalid code' });
    }

    db.run(
      `UPDATE users SET verified = 1, verify_code_hash = NULL, verify_code_expires = NULL, updated_at = ? WHERE id = ?`,
      [now(), user.id],
      function (updateErr) {
        if (updateErr) return res.status(500).json({ error: 'DB update error' });
        logAction(user.id, 'email_verified');
        res.json({ ok: true, message: 'Email verified' });
      }
    );
  });
});

app.post('/api/auth/reset-request', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });
  const normalizedEmail = String(email).toLowerCase().trim();

  db.get(`SELECT id, email FROM users WHERE email = ?`, [normalizedEmail], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.json({ ok: true });

    const code = code6();
    const expires = now() + 15 * 60 * 1000;
    db.run(
      `UPDATE users SET verify_code_hash = ?, verify_code_expires = ?, updated_at = ? WHERE id = ?`,
      [hashCode(code), expires, now(), user.id],
      async (updateErr) => {
        if (updateErr) return res.status(500).json({ error: 'DB update error' });
        await sendMail(
          normalizedEmail,
          'Сброс пароля NovaMessenger',
          `<div style="font-family:Arial,sans-serif;line-height:1.6"><h2>NovaMessenger</h2><p>Код для сброса пароля:</p><div style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</div><p>Код действует 15 минут.</p></div>`
        );
        res.json({ ok: true });
      }
    );
  });
});

app.post('/api/auth/reset-confirm', async (req, res) => {
  const { email, code, password } = req.body || {};
  if (!email || !code || !password) return res.status(400).json({ error: 'Missing fields' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password too short' });
  const normalizedEmail = String(email).toLowerCase().trim();

  db.get(`SELECT * FROM users WHERE email = ?`, [normalizedEmail], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.verify_code_hash || !user.verify_code_expires || user.verify_code_expires < now()) {
      return res.status(400).json({ error: 'Code expired' });
    }
    if (hashCode(String(code).trim()) !== user.verify_code_hash) {
      return res.status(400).json({ error: 'Invalid code' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    db.run(
      `UPDATE users SET password_hash = ?, verify_code_hash = NULL, verify_code_expires = NULL, updated_at = ? WHERE id = ?`,
      [passwordHash, now(), user.id],
      (updateErr) => {
        if (updateErr) return res.status(500).json({ error: 'DB update error' });
        res.json({ ok: true, message: 'Password updated' });
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const normalizedEmail = String(email).toLowerCase().trim();

  db.get(`SELECT * FROM users WHERE email = ?`, [normalizedEmail], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.verified) return res.status(403).json({ error: 'Email not verified' });

    const token = signToken(user);
    logAction(user.id, 'login');
    res.json({
      ok: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  });
});

app.get('/api/me', authRequired, (req, res) => {
  res.json({ ok: true, user: req.user });
});

app.get('/api/users', authRequired, adminOnly, (_req, res) => {
  db.all(`SELECT id, name, email, role, verified, created_at, updated_at FROM users ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ ok: true, users: rows });
  });
});

app.post('/api/users/:id/toggle-role', authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  db.get(`SELECT id, role FROM users WHERE id = ?`, [id], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const nextRole = user.role === 'admin' ? 'user' : 'admin';
    db.run(`UPDATE users SET role = ?, updated_at = ? WHERE id = ?`, [nextRole, now(), id], function (updateErr) {
      if (updateErr) return res.status(500).json({ error: 'DB update error' });
      logAction(req.user.id, `toggle_role:${id}:${nextRole}`);
      res.json({ ok: true, role: nextRole });
    });
  });
});

app.get('/api/dialogs', authRequired, (req, res) => {
  db.all(`
    SELECT d.id, d.user_a, d.user_b, d.created_at,
           ua.name AS a_name, ua.email AS a_email,
           ub.name AS b_name, ub.email AS b_email
    FROM dialogs d
    JOIN users ua ON ua.id = d.user_a
    JOIN users ub ON ub.id = d.user_b
    WHERE d.user_a = ? OR d.user_b = ?
    ORDER BY d.created_at DESC
  `, [req.user.id, req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ ok: true, dialogs: rows });
  });
});

app.post('/api/dialogs', authRequired, (req, res) => {
  const { partnerId } = req.body || {};
  const pid = Number(partnerId);
  if (!pid) return res.status(400).json({ error: 'Missing partnerId' });
  const a = Math.min(req.user.id, pid);
  const b = Math.max(req.user.id, pid);
  db.run(`INSERT OR IGNORE INTO dialogs (user_a, user_b, created_at) VALUES (?, ?, ?)`, [a, b, now()], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    logAction(req.user.id, `create_dialog:${pid}`);
    res.json({ ok: true, dialogId: this.lastID });
  });
});

app.get('/api/dialogs/:id/messages', authRequired, (req, res) => {
  const dialogId = Number(req.params.id);
  db.get(`SELECT * FROM dialogs WHERE id = ? AND (user_a = ? OR user_b = ?)`, [dialogId, req.user.id, req.user.id], (err, dialog) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!dialog) return res.status(403).json({ error: 'No access' });
    db.all(`SELECT * FROM messages WHERE dialog_id = ? ORDER BY created_at ASC`, [dialogId], (mErr, rows) => {
      if (mErr) return res.status(500).json({ error: 'DB error' });
      res.json({ ok: true, messages: rows });
    });
  });
});

app.post('/api/dialogs/:id/messages/text', authRequired, (req, res) => {
  const dialogId = Number(req.params.id);
  const { text } = req.body || {};
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'Missing text' });

  db.get(`SELECT * FROM dialogs WHERE id = ? AND (user_a = ? OR user_b = ?)`, [dialogId, req.user.id, req.user.id], (err, dialog) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!dialog) return res.status(403).json({ error: 'No access' });
    db.run(
      `INSERT INTO messages (dialog_id, sender_id, type, text, created_at) VALUES (?, ?, 'text', ?, ?)`,
      [dialogId, req.user.id, String(text).trim(), now()],
      function (insErr) {
        if (insErr) return res.status(500).json({ error: 'DB insert error' });
        logAction(req.user.id, `message_text:${dialogId}`);
        const message = {
          id: this.lastID,
          dialog_id: dialogId,
          sender_id: req.user.id,
          type: 'text',
          text: String(text).trim(),
          created_at: now()
        };
        io.to(`user:${dialog.user_a}`).emit('new_message', message);
        io.to(`user:${dialog.user_b}`).emit('new_message', message);
        res.json({ ok: true, messageId: this.lastID });
      }
    );
  });
});

app.post('/api/dialogs/:id/messages/file', authRequired, upload.single('file'), (req, res) => {
  const dialogId = Number(req.params.id);
  if (!req.file) return res.status(400).json({ error: 'No file' });
  db.get(`SELECT * FROM dialogs WHERE id = ? AND (user_a = ? OR user_b = ?)`, [dialogId, req.user.id, req.user.id], (err, dialog) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!dialog) return res.status(403).json({ error: 'No access' });
    const fileUrl = `/uploads/${req.file.filename}`;
    const type = req.file.mimetype.startsWith('audio/') ? 'voice' : 'file';
    db.run(
      `INSERT INTO messages (dialog_id, sender_id, type, file_url, file_name, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
      [dialogId, req.user.id, type, fileUrl, req.file.originalname, now()],
      function (insErr) {
        if (insErr) return res.status(500).json({ error: 'DB insert error' });
        logAction(req.user.id, `message_file:${dialogId}`);
        const message = {
          id: this.lastID,
          dialog_id: dialogId,
          sender_id: req.user.id,
          type,
          file_url: fileUrl,
          file_name: req.file.originalname,
          created_at: now()
        };
        io.to(`user:${dialog.user_a}`).emit('new_message', message);
        io.to(`user:${dialog.user_b}`).emit('new_message', message);
        res.json({ ok: true, messageId: this.lastID, fileUrl });
      }
    );
  });
});

app.get('/api/admin/logs', authRequired, adminOnly, (_req, res) => {
  db.all(`SELECT * FROM logs ORDER BY created_at DESC LIMIT 200`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ ok: true, logs: rows });
  });
});

app.get('/api/notifications', authRequired, (_req, res) => {
  db.all(`SELECT * FROM logs ORDER BY created_at DESC LIMIT 20`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ ok: true, notifications: rows });
  });
});

app.get('*', (_req, res) => {
  res.status(200).send(`
<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>NovaMessenger API</title></head>
<body style="font-family:Arial,sans-serif;padding:24px;line-height:1.6">
  <h1>NovaMessenger backend работает</h1>
  <p>Используй <code>/api/register</code>, <code>/api/verify-email</code>, <code>/api/login</code> и другие маршруты.</p>
</body></html>`);
});

io.on('connection', (socket) => {
  socket.on('auth', (token) => {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      socket.user = user;
      onlineUsers.set(user.id, { id: user.id, name: user.name, email: user.email, role: user.role, lastSeen: now() });
      socket.join(`user:${user.id}`);
      if ((user.email || '').toLowerCase() === OWNER_EMAIL || user.role === 'admin') {
        socket.join('admins');
      }
      io.emit('presence:update', [...onlineUsers.values()]);
      socket.emit('ready', { ok: true, user });
    } catch {
      socket.emit('error_message', 'Invalid token');
    }
  });

  socket.on('send_message', (payload) => {
    if (!socket.user) return;
    const { dialogId, text } = payload || {};
    if (!dialogId || !text) return;

    db.get(`SELECT * FROM dialogs WHERE id = ? AND (user_a = ? OR user_b = ?)`, [Number(dialogId), socket.user.id, socket.user.id], (err, dialog) => {
      if (err || !dialog) return;
      db.run(
        `INSERT INTO messages (dialog_id, sender_id, type, text, created_at) VALUES (?, ?, 'text', ?, ?)`,
        [Number(dialogId), socket.user.id, String(text).trim(), now()],
        function (insErr) {
          if (insErr) return;
          const message = { id: this.lastID, dialog_id: Number(dialogId), sender_id: socket.user.id, type: 'text', text: String(text).trim(), created_at: now() };
          io.to(`user:${dialog.user_a}`).emit('new_message', message);
          io.to(`user:${dialog.user_b}`).emit('new_message', message);
        }
      );
    });
  });

  socket.on('disconnect', () => {
    if (socket.user?.id) {
      const existing = onlineUsers.get(socket.user.id);
      if (existing) {
        existing.lastSeen = now();
        onlineUsers.set(socket.user.id, existing);
      }
      io.emit('presence:update', [...onlineUsers.values()]);
    }
  });
});

server.listen(PORT, async () => {
  console.log(`NovaMessenger running on http://localhost:${PORT}`);
  db.get(`SELECT id FROM users WHERE email = ?`, [OWNER_EMAIL], async (err, owner) => {
    if (err) return console.error(err);
    if (!owner) {
      const passwordHash = await bcrypt.hash('123456', 10);
      db.run(
        `INSERT INTO users (name, email, password_hash, role, verified, created_at, updated_at) VALUES (?, ?, ?, 'admin', 1, ?, ?)`,
        ['Owner', OWNER_EMAIL, passwordHash, now(), now()],
        (insErr) => {
          if (insErr) console.error(insErr);
          else console.log(`Owner account created: ${OWNER_EMAIL} / 123456`);
        }
      );
    }
  });
});
