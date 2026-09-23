'use strict';
/**
 * Crossing Thresholds Issue Tracker — standalone server.
 * Own email/password accounts, own JSON-file database. No external services.
 *
 * Run: npm install && npm start
 * Config (optional environment variables):
 *   PORT              default 3000
 *   SESSION_SECRET    set this in production! Random each boot otherwise,
 *                      which logs everyone out whenever the server restarts.
 *   COOKIE_SECURE     set to "true" once you are serving over HTTPS
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const COOKIE_NAME = 'ctt_session';
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

if (!process.env.SESSION_SECRET) {
  console.warn('[warn] SESSION_SECRET is not set. Using a random secret for this run — ' +
    'everyone will be signed out the next time the server restarts. Set SESSION_SECRET ' +
    'in your environment for real deployments.');
}
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const ROLES = ['staff', 'director', 'board', 'admin'];
const CATS = ['Computers and devices', 'Network and Wi-Fi', 'Accounts and passwords',
  'Software and licenses', 'Printers and copiers', 'Projectors and AV', 'Security or safety', 'Other'];
const PRIORITIES = ['urgent', 'high', 'normal', 'low'];
const DISTRICT = 'District office';

// Which starting statuses each transition is allowed from.
const ALLOWED_FROM = {
  escalated: ['submitted', 'needs_info'],
  info_requested: ['submitted'],
  info_provided: ['needs_info'],
  taken: ['with_board', 'in_progress'],
  returned: ['with_board', 'in_progress'],
  resolved: ['submitted', 'needs_info', 'with_board', 'in_progress'],
  reopened: ['resolved'],
  priority: ['submitted', 'needs_info', 'with_board', 'in_progress'],
  commented: ['submitted', 'needs_info', 'with_board', 'in_progress', 'resolved']
};
const NOTE_REQUIRED = ['info_requested', 'info_provided', 'returned', 'resolved', 'reopened', 'commented'];

// ---------------------------------------------------------------------------
// Tiny JSON-file store. Fine for a district-scale tool; writes are queued so
// two requests never interleave a write to the file.
// ---------------------------------------------------------------------------
function loadDB() {
  if (!fs.existsSync(DATA_FILE)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const initial = { users: {}, schools: [], issues: {} };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
const db = loadDB();
let saveChain = Promise.resolve();
function persist() {
  saveChain = saveChain.then(() => new Promise((resolve, reject) => {
    const tmp = DATA_FILE + '.tmp';
    fs.writeFile(tmp, JSON.stringify(db, null, 2), (err) => {
      if (err) return reject(err);
      fs.rename(tmp, DATA_FILE, (err2) => (err2 ? reject(err2) : resolve()));
    });
  })).catch((e) => console.error('[db] write failed:', e));
  return saveChain;
}
function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role, school: u.school || '', createdAt: u.createdAt };
}
function findUserByEmail(email) {
  email = String(email || '').trim().toLowerCase();
  return Object.values(db.users).find((u) => u.email === email) || null;
}
function directorCount() {
  return Object.values(db.users).filter((u) => u.role === 'director').length;
}
function demoteOtherDirectors(exceptId) {
  Object.values(db.users).forEach((u) => {
    if (u.role === 'director' && u.id !== exceptId) u.role = 'staff';
  });
}

// ---------------------------------------------------------------------------
// Signed session cookie — a small HMAC token, no session store needed.
// ---------------------------------------------------------------------------
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const [body, sig] = token.split('.');
  try {
    const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    const a = Buffer.from(sig), b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}
function setSessionCookie(res, userId) {
  const token = signToken({ uid: userId, exp: Date.now() + TOKEN_TTL_MS });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, maxAge: TOKEN_TTL_MS
  });
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function isEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '')); }

function attachUser(req, res, next) {
  const payload = verifyToken(req.cookies[COOKIE_NAME]);
  req.user = payload ? db.users[payload.uid] || null : null;
  next();
}
app.use(attachUser);

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'not_signed_in', message: 'Sign in to continue.' });
  next();
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden', message: 'You do not have permission to do that.' });
    }
    next();
  };
}
function isDirectorLike(u) { return u && (u.role === 'director' || u.role === 'admin'); }

// ---- bootstrap / auth ----
app.get('/api/bootstrap', (req, res) => {
  res.json({ needsSetup: Object.keys(db.users).length === 0 });
});

app.post('/api/setup', async (req, res) => {
  if (Object.keys(db.users).length > 0) {
    return res.status(409).json({ error: 'already_set_up', message: 'Setup has already been completed. Sign in instead.' });
  }
  const { email, password, name } = req.body || {};
  if (!isEmail(email)) return res.status(400).json({ error: 'invalid_email', message: 'Enter a valid email address.' });
  if (!password || String(password).length < 8) return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters.' });
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'missing_name', message: 'Enter your name.' });
  const id = crypto.randomUUID();
  const user = {
    id, email: String(email).trim().toLowerCase(), name: String(name).trim(),
    passwordHash: await bcrypt.hash(String(password), 10),
    role: 'admin', school: '', createdAt: Date.now()
  };
  db.users[id] = user;
  await persist();
  setSessionCookie(res, id);
  res.json({ user: publicUser(user) });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = findUserByEmail(email);
  if (!user) return res.status(401).json({ error: 'invalid_credentials', message: 'Incorrect email or password.' });
  const ok = await bcrypt.compare(String(password || ''), user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials', message: 'Incorrect email or password.' });
  setSessionCookie(res, user.id);
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const ok = await bcrypt.compare(String(currentPassword || ''), req.user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials', message: 'Your current password is incorrect.' });
  if (!newPassword || String(newPassword).length < 8) return res.status(400).json({ error: 'weak_password', message: 'New password must be at least 8 characters.' });
  req.user.passwordHash = await bcrypt.hash(String(newPassword), 10);
  await persist();
  res.json({ ok: true });
});

// ---- users (read: any signed-in user, for name lookups; write: admin only) ----
app.get('/api/users', requireAuth, (req, res) => {
  res.json({ users: Object.values(db.users).map(publicUser).sort((a, b) => a.name.localeCompare(b.name)) });
});

app.post('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { email, name, password, role, school } = req.body || {};
  if (!isEmail(email)) return res.status(400).json({ error: 'invalid_email', message: 'Enter a valid email address.' });
  if (findUserByEmail(email)) return res.status(409).json({ error: 'email_taken', message: 'That email already has an account.' });
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'missing_name', message: 'Enter a name.' });
  if (!password || String(password).length < 8) return res.status(400).json({ error: 'weak_password', message: 'Set a temporary password of at least 8 characters, then share it with them directly.' });
  const r = ROLES.includes(role) ? role : 'staff';
  if (r === 'admin') return res.status(400).json({ error: 'invalid_role', message: 'New accounts cannot be created as admin. Promote them after they sign in once.' });
  const id = crypto.randomUUID();
  const user = {
    id, email: String(email).trim().toLowerCase(), name: String(name).trim(),
    passwordHash: await bcrypt.hash(String(password), 10),
    role: r, school: r === 'staff' ? String(school || '').trim() : '', createdAt: Date.now()
  };
  let note = null;
  if (r === 'director' && directorCount() > 0) { demoteOtherDirectors(id); note = 'The previous director was moved to tech staff — there can only be one director.'; }
  db.users[id] = user;
  await persist();
  res.json({ user: publicUser(user), note });
});

app.patch('/api/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const user = db.users[req.params.id];
  if (!user) return res.status(404).json({ error: 'not_found', message: 'That person no longer exists.' });
  const { role, school, newPassword, name } = req.body || {};
  let note = null;
  if (role && ROLES.includes(role) && role !== user.role) {
    if (role === 'admin' && user.id !== req.user.id) {
      // allow promoting others to admin explicitly if the acting admin chooses to
    }
    if (role === 'director') { demoteOtherDirectors(user.id); note = 'Any previous director was moved to tech staff — there can only be one director.'; }
    user.role = role;
    if (role !== 'staff') user.school = '';
  }
  if (typeof school === 'string' && user.role === 'staff') user.school = school.trim();
  if (typeof name === 'string' && name.trim()) user.name = name.trim();
  if (newPassword) {
    if (String(newPassword).length < 8) return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters.' });
    user.passwordHash = await bcrypt.hash(String(newPassword), 10);
  }
  await persist();
  res.json({ user: publicUser(user), note });
});

app.delete('/api/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'cannot_remove_self', message: 'You cannot remove your own account.' });
  if (!db.users[req.params.id]) return res.status(404).json({ error: 'not_found', message: 'That person no longer exists.' });
  delete db.users[req.params.id];
  await persist();
  res.json({ ok: true });
});

// ---- schools ----
app.get('/api/schools', requireAuth, (req, res) => {
  res.json({ schools: db.schools });
});
app.post('/api/schools', requireAuth, requireRole('admin', 'director'), async (req, res) => {
  const name = String((req.body || {}).name || '').trim();
  if (!name) return res.status(400).json({ error: 'missing_name', message: 'Enter a school name.' });
  if (db.schools.some((s) => s.toLowerCase() === name.toLowerCase())) return res.status(409).json({ error: 'duplicate', message: 'That school is already on the list.' });
  db.schools.push(name);
  await persist();
  res.json({ schools: db.schools });
});
app.delete('/api/schools/:name', requireAuth, requireRole('admin', 'director'), async (req, res) => {
  const name = decodeURIComponent(req.params.name);
  db.schools = db.schools.filter((s) => s !== name);
  await persist();
  res.json({ schools: db.schools });
});

// ---- issues ----
app.get('/api/issues', requireAuth, (req, res) => {
  res.json({ issues: Object.values(db.issues).sort((a, b) => b.updatedAt - a.updatedAt) });
});

app.post('/api/issues', requireAuth, async (req, res) => {
  const { title, description, school, category, room, priority } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'missing_title', message: 'Add a short summary.' });
  if (!description || !String(description).trim()) return res.status(400).json({ error: 'missing_description', message: 'Describe what is happening.' });
  if (!school || !String(school).trim()) return res.status(400).json({ error: 'missing_school', message: 'Choose the school this issue is at.' });
  const id = crypto.randomUUID();
  const now = Date.now();
  const issue = {
    id, title: String(title).trim().slice(0, 200), description: String(description).trim().slice(0, 4000),
    school: String(school).trim(), category: CATS.includes(category) ? category : 'Other',
    room: String(room || '').trim().slice(0, 80),
    priority: PRIORITIES.includes(priority) ? priority : 'normal',
    status: 'submitted', reporterId: req.user.id, assigneeId: null,
    createdAt: now, updatedAt: now,
    history: [{ at: now, by: req.user.id, type: 'submitted' }]
  };
  db.issues[id] = issue;
  await persist();
  res.json({ issue });
});

app.patch('/api/issues/:id', requireAuth, async (req, res) => {
  const issue = db.issues[req.params.id];
  if (!issue) return res.status(404).json({ error: 'not_found', message: 'This issue no longer exists.' });
  const { type, note, assigneeId, to } = req.body || {};
  if (!ALLOWED_FROM[type]) return res.status(400).json({ error: 'invalid_type', message: 'Unrecognized action.' });
  if (!ALLOWED_FROM[type].includes(issue.status)) {
    return res.status(409).json({ error: 'stale_status', message: 'Someone else just changed this issue. Refresh and try again.' });
  }
  if (NOTE_REQUIRED.includes(type) && (!note || !String(note).trim())) {
    return res.status(400).json({ error: 'missing_note', message: 'Add a note before doing that.' });
  }
  const role = req.user.role, uid = req.user.id;
  const perm = {
    escalated: isDirectorLike(req.user),
    info_requested: isDirectorLike(req.user),
    info_provided: issue.reporterId === uid,
    taken: role === 'board',
    returned: role === 'board',
    resolved: role === 'board' || isDirectorLike(req.user),
    reopened: issue.reporterId === uid || isDirectorLike(req.user),
    priority: isDirectorLike(req.user),
    commented: true
  }[type];
  if (!perm) return res.status(403).json({ error: 'forbidden', message: 'You do not have permission to take that action on this issue.' });

  const now = Date.now();
  const ev = { at: now, by: uid, type };
  if (note) ev.note = String(note).trim().slice(0, 2000);
  const patch = { updatedAt: now };
  if (type === 'escalated') {
    patch.status = 'with_board';
    patch.assigneeId = (assigneeId && db.users[assigneeId] && db.users[assigneeId].role === 'board') ? assigneeId : null;
    if (patch.assigneeId) ev.assignee = patch.assigneeId;
  } else if (type === 'info_requested') { patch.status = 'needs_info'; }
  else if (type === 'info_provided') { patch.status = 'submitted'; }
  else if (type === 'taken') { patch.status = 'in_progress'; patch.assigneeId = uid; }
  else if (type === 'returned') { patch.status = 'submitted'; patch.assigneeId = null; }
  else if (type === 'resolved') {
    patch.status = 'resolved'; patch.resolvedAt = now; patch.resolvedBy = uid;
    if (!issue.assigneeId && role === 'board') patch.assigneeId = uid;
  } else if (type === 'reopened') { patch.status = 'submitted'; patch.assigneeId = null; patch.resolvedAt = null; patch.resolvedBy = null; }
  else if (type === 'priority') {
    if (!PRIORITIES.includes(to)) return res.status(400).json({ error: 'invalid_priority', message: 'Unrecognized priority.' });
    patch.priority = to; ev.to = to;
  }
  Object.assign(issue, patch);
  issue.history.push(ev);
  await persist();
  res.json({ issue });
});

// SPA fallback — everything not /api/* serves the client
app.get(/^(?!\/api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Crossing Thresholds Issue Tracker listening on http://localhost:${PORT}`);
});
