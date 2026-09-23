const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT) || 6060;
const MAX_USERS = 20;
const DEFAULT_QUOTA_BYTES = 1024 ** 3;
const MAX_QUOTA_BYTES = 1024 ** 4;
const MAX_FILE_SIZE = 200 * 1024 * 1024;
const SESSION_TTL = 30 * 60 * 1000;
const HASH_ITERATIONS = 210000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const FILES_FILE = path.join(DATA_DIR, 'files.json');
const LEGACY_NOTES_FILE = path.join(DATA_DIR, 'notes.json');
const ANNOUNCEMENT_FILE = path.join(DATA_DIR, 'announcement.json');
const SHARES_FILE = path.join(DATA_DIR, 'shares.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
const proxyHops = Math.max(0, parseInt(process.env.TRUST_PROXY_HOPS, 10) || 0);
if (proxyHops > 0) app.set('trust proxy', proxyHops);

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}
function writeJson(file, value) {
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(temp, file);
}
const savedAnnouncement = readJson(ANNOUNCEMENT_FILE, null);
let announcement = savedAnnouncement && typeof savedAnnouncement === 'object' && !Array.isArray(savedAnnouncement)
  ? {
      title: String(savedAnnouncement.title || '团队公告').slice(0, 80),
      content: String(savedAnnouncement.content || '暂未发布公告。').slice(0, 4000),
      updatedAt: Number(savedAnnouncement.updatedAt) || Date.now(),
      updatedBy: String(savedAnnouncement.updatedBy || ''),
    }
  : { title: '团队公告', content: '暂未发布公告。', updatedAt: Date.now(), updatedBy: '' };
if (!savedAnnouncement) writeJson(ANNOUNCEMENT_FILE, announcement);
function randomId(bytes = 16) { return crypto.randomBytes(bytes).toString('hex'); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.pbkdf2(password, salt, HASH_ITERATIONS, 32, 'sha256', (err, key) => {
    if (err) return reject(err);
    resolve({ salt, hash: key.toString('hex') });
  }));
}
function passwordMatches(password, user) {
  return new Promise((resolve, reject) => crypto.pbkdf2(password, user.salt, HASH_ITERATIONS, 32, 'sha256', (err, key) => {
    if (err) return reject(err);
    const actual = key.toString('hex');
    resolve(actual.length === user.hash.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(user.hash)));
  }));
}

let users = readJson(USERS_FILE, []);
const storedFileRecords = readJson(FILES_FILE, {});
let fileRecords = Object.assign(Object.create(null), storedFileRecords);
const storedFileShares = readJson(SHARES_FILE, {});
let fileShares = Object.assign(Object.create(null), storedFileShares);
const storedAuditLogs = readJson(AUDIT_FILE, []);
let auditLogs = Array.isArray(storedAuditLogs) ? storedAuditLogs.slice(-3000) : [];
const legacyNotes = readJson(LEGACY_NOTES_FILE, {});
if (!Array.isArray(users)) throw new Error('data/users.json 格式错误');
if (!storedFileRecords || Array.isArray(storedFileRecords) || typeof storedFileRecords !== 'object') throw new Error('data/files.json 格式错误');
if (!storedFileShares || Array.isArray(storedFileShares) || typeof storedFileShares !== 'object') throw new Error('data/shares.json 格式错误');
if (!Array.isArray(storedAuditLogs)) throw new Error('data/audit.json 格式错误');
let nextAuditId = auditLogs.reduce((max, row) => Math.max(max, Number(row?.id) || 0), 0) + 1;

// First launch: create the administrator from environment variables, never from source defaults.
if (users.length === 0) {
  const username = (process.env.ADMIN_USERNAME || '').trim();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!username || password.length < 8) {
    throw new Error('首次启动请设置 ADMIN_USERNAME 和至少 8 位的 ADMIN_PASSWORD 环境变量');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, HASH_ITERATIONS, 32, 'sha256').toString('hex');
  users.push({ id: randomId(), username, role: 'admin', isSuperAdmin: true, active: true, quotaBytes: DEFAULT_QUOTA_BYTES, salt, hash, createdAt: Date.now() });
  writeJson(USERS_FILE, users);
}
// Keep the original admin account as the single super administrator on existing installs.
const rootAdmin = users.find(user => user.username.toLowerCase() === 'admin')
  || users.find(user => user.role === 'admin' && user.isSuperAdmin)
  || users.find(user => user.role === 'admin');
let superAdminUpdated = false;
for (const user of users) {
  const isSuperAdmin = Boolean(rootAdmin && user.id === rootAdmin.id);
  if (isSuperAdmin && user.role !== 'admin') {
    user.role = 'admin';
    superAdminUpdated = true;
  }
  if (user.isSuperAdmin !== isSuperAdmin) {
    user.isSuperAdmin = isSuperAdmin;
    superAdminUpdated = true;
  }
}
if (superAdminUpdated) writeJson(USERS_FILE, users);
let quotaDefaultsAdded = false;
for (const user of users) {
  if (!Number.isSafeInteger(user.quotaBytes) || user.quotaBytes <= 0) {
    user.quotaBytes = DEFAULT_QUOTA_BYTES;
    quotaDefaultsAdded = true;
  }
}
if (quotaDefaultsAdded) writeJson(USERS_FILE, users);

// Adopt files from the original single-user version into the shared team space.
let migrated = false;
for (const name of fs.readdirSync(UPLOAD_DIR)) {
  if (name.startsWith('.') || !fs.statSync(path.join(UPLOAD_DIR, name)).isFile() || fileRecords[name]) continue;
  const stat = fs.statSync(path.join(UPLOAD_DIR, name));
  fileRecords[name] = { name, size: stat.size, mtime: stat.mtimeMs, scope: 'team', ownerId: users[0].id, note: String(legacyNotes[name] || '') };
  migrated = true;
}
if (migrated) writeJson(FILES_FILE, fileRecords);

const sessions = new Map();
const loginAttempts = new Map();
const loginCaptchas = new Map();
const captchaIssuance = new Map();
const shareCodeAttempts = new Map();
const shareDownloadGrants = new Map();
const maxAttempts = 8;
function getClientIP(req) { return req.ip || req.socket.remoteAddress || 'unknown'; }
function makeCaptchaSvg(answer) {
  const palette = ['#334f9b', '#6a438f', '#2b746d', '#8a5638'];
  const chars = [...answer].map((char, index) => {
    const x = 22 + index * 27 + crypto.randomInt(-2, 3);
    const y = 34 + crypto.randomInt(-5, 6);
    const angle = crypto.randomInt(-16, 17);
    const color = palette[crypto.randomInt(0, palette.length)];
    return `<text x="${x}" y="${y}" fill="${color}" transform="rotate(${angle} ${x} ${y})">${char}</text>`;
  }).join('');
  const lines = Array.from({ length: 5 }, () => {
    const x1 = crypto.randomInt(0, 145), y1 = crypto.randomInt(0, 48);
    const x2 = crypto.randomInt(0, 145), y2 = crypto.randomInt(0, 48);
    return `<path d="M${x1} ${y1} L${x2} ${y2}" stroke="#9aa8bf" stroke-width="${crypto.randomInt(1, 3)}" opacity=".42"/>`;
  }).join('');
  const dots = Array.from({ length: 28 }, () => `<circle cx="${crypto.randomInt(2, 144)}" cy="${crypto.randomInt(2, 46)}" r="${crypto.randomInt(1, 3)}" fill="#8090a8" opacity=".45"/>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="148" height="50" viewBox="0 0 148 50"><rect width="148" height="50" rx="6" fill="#f2f5fa"/>${lines}${dots}<g font-family="Arial,sans-serif" font-size="25" font-weight="700" letter-spacing="2">${chars}</g></svg>`;
}
function isBanned(ip) {
  const row = loginAttempts.get(ip);
  if (!row) return false;
  if (row.until <= Date.now()) { loginAttempts.delete(ip); return false; }
  return row.count >= maxAttempts;
}
const loginCleanup = setInterval(() => {
  const now = Date.now();
  for (const [ip, row] of loginAttempts) if (row.until <= now) loginAttempts.delete(ip);
  while (loginAttempts.size > 2048) loginAttempts.delete(loginAttempts.keys().next().value);
  for (const [id, challenge] of loginCaptchas) if (challenge.expiresAt <= now) loginCaptchas.delete(id);
  while (loginCaptchas.size > 2048) loginCaptchas.delete(loginCaptchas.keys().next().value);
  for (const [ip, row] of captchaIssuance) if (row.until <= now) captchaIssuance.delete(ip);
  while (captchaIssuance.size > 2048) captchaIssuance.delete(captchaIssuance.keys().next().value);
}, 5 * 60 * 1000);
loginCleanup.unref();
function auth(req, res, next) {
  const token = req.get('x-auth-token');
  const session = token && sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'unauthorized', message: '登录已过期，请重新登录' });
  }
  const user = users.find(row => row.id === session.userId && row.active);
  if (!user) { sessions.delete(token); return res.status(401).json({ error: 'unauthorized' }); }
  session.expiresAt = Date.now() + SESSION_TTL;
  req.user = user;
  req.sessionToken = token;
  next();
}
const sessionCleanup = setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) if (session.expiresAt <= now) sessions.delete(token);
}, 10 * 60 * 1000);
sessionCleanup.unref();
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
  next();
}
function persistFiles() { writeJson(FILES_FILE, fileRecords); }
function persistShares() { writeJson(SHARES_FILE, fileShares); }
function persistAuditLogs() { writeJson(AUDIT_FILE, auditLogs); }
function recordAudit(req, action, detail = '') {
  const row = {
    id: nextAuditId++,
    time: Date.now(),
    actor: req?.user?.username || '访客',
    actorId: req?.user?.id || '',
    action: String(action).slice(0, 60),
    detail: String(detail).slice(0, 400),
    ip: req ? String(getClientIP(req)).slice(0, 80) : '',
  };
  auditLogs.push(row);
  if (auditLogs.length > 3000) auditLogs = auditLogs.slice(-3000);
  try { persistAuditLogs(); } catch (error) { console.error('Failed to persist audit log:', error.message); }
}
function shareTokenDigest(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function makeShareCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 8 }, () => alphabet[crypto.randomInt(0, alphabet.length)]).join('');
}
function cleanupExpiredShares() {
  const now = Date.now();
  let changed = false;
  for (const [id, share] of Object.entries(fileShares)) {
    if (!share || !Number.isFinite(share.expiresAt) || share.expiresAt <= now) {
      delete fileShares[id];
      changed = true;
    }
  }
  if (changed) persistShares();
}
function cleanupShareRuntimeState() {
  const now = Date.now();
  for (const [key, row] of shareCodeAttempts) if (row.until <= now) shareCodeAttempts.delete(key);
  for (const [grant, row] of shareDownloadGrants) if (row.expiresAt <= now) shareDownloadGrants.delete(grant);
  while (shareCodeAttempts.size > 2048) shareCodeAttempts.delete(shareCodeAttempts.keys().next().value);
  while (shareDownloadGrants.size > 2048) shareDownloadGrants.delete(shareDownloadGrants.keys().next().value);
}
cleanupExpiredShares();
const shareCleanup = setInterval(() => { cleanupExpiredShares(); cleanupShareRuntimeState(); }, 5 * 60 * 1000);
shareCleanup.unref();
function getUserUsageBytes(userId) {
  let used = 0;
  for (const record of Object.values(fileRecords)) if (record.ownerId === userId) used += Number(record.size) || 0;
  return used;
}
function canRead(req, record) {
  return record && (record.scope === 'team' || record.ownerId === req.user.id);
}
function canChange(req, record) {
  return record && (record.ownerId === req.user.id || (record.scope === 'team' && req.user.role === 'admin'));
}
function getRecord(name) {
  if (typeof name !== 'string' || !name || name.includes('/') || name.includes('\\') || name.includes('\0')) return null;
  return fileRecords[name] || null;
}
function getFilePath(name) { return path.join(UPLOAD_DIR, name); }
function safeName(original) {
  const decoded = Buffer.from(String(original || ''), 'latin1').toString('utf8');
  const base = path.basename(decoded.replace(/\\/g, '/')).replace(/[\x00-\x1f]/g, '_').trim();
  return base && base !== '.' && base !== '..' ? base.slice(0, 240) : '未命名文件';
}
function uniqueName(original) {
  const ext = path.extname(original).slice(0, 32);
  const stem = original.slice(0, original.length - ext.length);
  let candidate = original;
  let i = 1;
  while (fs.existsSync(getFilePath(candidate))) {
    candidate = `${stem.slice(0, 220)}(${i++})${ext}`;
  }
  return candidate;
}

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => cb(null, `.upload-${Date.now()}-${randomId(8)}.tmp`),
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 4 },
});

app.get('/api/captcha', (req, res) => {
  const ip = getClientIP(req);
  const now = Date.now();
  const issuance = captchaIssuance.get(ip);
  if (issuance && issuance.until > now && issuance.count >= 30) return res.status(429).json({ error: '验证码请求过于频繁，请稍后再试' });
  const nextIssuance = issuance && issuance.until > now ? issuance : { count: 0, until: now + 60 * 1000 };
  nextIssuance.count++;
  captchaIssuance.set(ip, nextIssuance);

  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let answer = '';
  for (let index = 0; index < 5; index++) answer += alphabet[crypto.randomInt(0, alphabet.length)];
  const id = randomId(16);
  loginCaptchas.set(id, { answer, ip, expiresAt: now + 2 * 60 * 1000 });
  const svg = makeCaptchaSvg(answer);
  res.set('Cache-Control', 'no-store, max-age=0');
  res.json({ id, image: `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}` });
});
app.get('/api/login-status', (req, res) => res.json({ banned: isBanned(getClientIP(req)), maxAttempts }));
app.post('/api/login', async (req, res) => {
  const ip = getClientIP(req);
  if (isBanned(ip)) return res.status(429).json({ error: '登录失败次数过多，请稍后再试', banned: true });
  const { username, password, captchaId, captcha } = req.body || {};
  const attemptedUsername = String(username || '').trim().slice(0, 40);
  const challenge = typeof captchaId === 'string' ? loginCaptchas.get(captchaId) : null;
  if (captchaId) loginCaptchas.delete(captchaId);
  const captchaValid = challenge && challenge.ip === ip && challenge.expiresAt > Date.now()
    && typeof captcha === 'string' && captcha.trim().toUpperCase() === challenge.answer;
  if (!captchaValid) {
    const current = loginAttempts.get(ip) || { count: 0, until: Date.now() + 15 * 60 * 1000 };
    current.count++;
    loginAttempts.set(ip, current);
    recordAudit(req, 'login.failed', `账号 ${attemptedUsername || '（空）'}：验证码错误`);
    return res.status(401).json({ error: '验证码错误或已过期，请重试', remaining: Math.max(0, maxAttempts - current.count), banned: current.count >= maxAttempts });
  }
  const normalizedUsername = String(username || '').trim().toLowerCase();
  const user = users.find(row => row.username.toLowerCase() === normalizedUsername && row.active);
  const valid = user && typeof password === 'string' && await passwordMatches(password, user);
  if (!valid) {
    const current = loginAttempts.get(ip) || { count: 0, until: Date.now() + 15 * 60 * 1000 };
    current.count++;
    loginAttempts.set(ip, current);
    recordAudit(req, 'login.failed', `账号 ${attemptedUsername || '（空）'}：凭据错误`);
    return res.status(401).json({ error: '用户名或密码错误', remaining: Math.max(0, maxAttempts - current.count), banned: current.count >= maxAttempts });
  }
  loginAttempts.delete(ip);
  const userSessions = [...sessions].filter(([, session]) => session.userId === user.id);
  while (userSessions.length >= 3) sessions.delete(userSessions.shift()[0]);
  const token = randomId(32);
  sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_TTL });
  req.user = user;
  recordAudit(req, 'login.success', '登录成功');
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});
app.post('/api/logout', auth, (req, res) => { recordAudit(req, 'logout', '退出登录'); sessions.delete(req.sessionToken); res.json({ success: true }); });
app.get('/api/me', auth, (req, res) => res.json({
  id: req.user.id,
  username: req.user.username,
  role: req.user.role,
  isSuperAdmin: Boolean(req.user.isSuperAdmin),
  usedBytes: getUserUsageBytes(req.user.id),
  quotaBytes: req.user.quotaBytes,
}));
app.get('/api/announcement', auth, (req, res) => res.json({ announcement }));
app.get('/api/admin/audit', auth, (req, res) => {
  if (!req.user.isSuperAdmin) return res.status(403).json({ error: '只有超级管理员可以查看系统日志' });
  const before = parseInt(req.query.before, 10);
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));
  const eligible = auditLogs.filter(row => !Number.isSafeInteger(before) || before <= 0 || row.id < before);
  const logs = eligible.slice(-limit).reverse();
  res.json({ logs, hasMore: eligible.length > logs.length });
});
app.put('/api/announcement', auth, adminOnly, (req, res) => {
  const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
  const content = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
  if (!title || title.length > 80) return res.status(400).json({ error: '公告标题需为 1–80 个字符' });
  if (!content || content.length > 4000) return res.status(400).json({ error: '公告内容需为 1–4000 个字符' });
  announcement = { title, content, updatedAt: Date.now(), updatedBy: req.user.username };
  writeJson(ANNOUNCEMENT_FILE, announcement);
  recordAudit(req, 'announcement.updated', `更新公告：${title}`);
  res.json({ success: true, announcement });
});
app.post('/api/change-password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (typeof oldPassword !== 'string' || !(await passwordMatches(oldPassword, req.user))) return res.status(400).json({ error: '当前密码不正确' });
  if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) return res.status(400).json({ error: '新密码长度需为 8–128 位' });
  Object.assign(req.user, await hashPassword(newPassword));
  writeJson(USERS_FILE, users);
  for (const [token, session] of sessions) if (session.userId === req.user.id) sessions.delete(token);
  const token = randomId(32);
  sessions.set(token, { userId: req.user.id, expiresAt: Date.now() + SESSION_TTL });
  recordAudit(req, 'password.changed', '修改个人密码');
  res.json({ success: true, token });
});

app.get('/api/users', auth, adminOnly, (req, res) => res.json({ users: users.map(({ id, username, role, isSuperAdmin, active, createdAt, quotaBytes }) => ({ id, username, role, isSuperAdmin: Boolean(isSuperAdmin), active, createdAt, quotaBytes, usedBytes: getUserUsageBytes(id) })) }));
app.post('/api/users', auth, adminOnly, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = req.body?.password;
  if (!/^[\p{L}\p{N}_.@-]{2,40}$/u.test(username)) return res.status(400).json({ error: '账号需为 2–40 位字母、数字或 . _ @ -' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) return res.status(400).json({ error: '初始密码长度需为 8–128 位' });
  if (users.some(row => row.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: '账号已存在' });
  if (users.length >= MAX_USERS) return res.status(409).json({ error: `最多支持 ${MAX_USERS} 个账号` });
  const credentials = await hashPassword(password);
  if (users.length >= MAX_USERS) return res.status(409).json({ error: `最多支持 ${MAX_USERS} 个账号` });
  if (users.some(row => row.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: '账号已存在' });
  const user = { id: randomId(), username, role: 'member', isSuperAdmin: false, active: true, quotaBytes: DEFAULT_QUOTA_BYTES, ...credentials, createdAt: Date.now() };
  users.push(user);
  writeJson(USERS_FILE, users);
  recordAudit(req, 'member.created', `创建成员：${username}`);
  res.status(201).json({ success: true, user: { id: user.id, username: user.username, role: user.role, active: user.active } });
});
app.patch('/api/users/:id', auth, adminOnly, async (req, res) => {
  const user = users.find(row => row.id === req.params.id);
  if (!user) return res.status(404).json({ error: '成员不存在' });
  const previous = { role: user.role, active: user.active, quotaBytes: user.quotaBytes };
  if (user.id === req.user.id && req.body?.active === false) return res.status(400).json({ error: '不能停用当前管理员账号' });
  if (req.body?.role !== undefined && !['admin', 'member'].includes(req.body.role)) return res.status(400).json({ error: '角色无效' });
  if (req.body?.role !== undefined && !req.user.isSuperAdmin) return res.status(403).json({ error: '只有超级管理员可以设置管理员权限' });
  if (user.isSuperAdmin && req.body?.role === 'member') return res.status(403).json({ error: '不能取消超级管理员 admin 的权限' });
  if (user.isSuperAdmin && req.body?.active === false) return res.status(403).json({ error: '不能停用超级管理员 admin' });
  if (user.isSuperAdmin && !req.user.isSuperAdmin && typeof req.body?.password === 'string') return res.status(403).json({ error: '只有超级管理员可以重设超级管理员密码' });
  if (user.id === req.user.id && req.body?.role === 'member') return res.status(400).json({ error: '不能取消当前登录账号的管理员权限' });
  if (req.body?.role === 'member' && user.role === 'admin' && user.active && users.filter(row => row.role === 'admin' && row.active).length <= 1) return res.status(400).json({ error: '至少保留一名启用的管理员' });
  if (req.body?.active === false && user.role === 'admin' && users.filter(row => row.role === 'admin' && row.active).length <= 1) return res.status(400).json({ error: '至少保留一名启用的管理员' });
  if (typeof req.body?.active === 'boolean') user.active = req.body.active;
  if (req.body?.role !== undefined) user.role = req.body.role;
  if (req.body?.quotaBytes !== undefined) {
    const quotaBytes = Number(req.body.quotaBytes);
    if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 0.1 * DEFAULT_QUOTA_BYTES || quotaBytes > MAX_QUOTA_BYTES) {
      return res.status(400).json({ error: '容量需设置为 0.1–1024 GB' });
    }
    user.quotaBytes = quotaBytes;
  }
  if (typeof req.body?.password === 'string') {
    if (req.body.password.length < 8 || req.body.password.length > 128) return res.status(400).json({ error: '密码长度需为 8–128 位' });
    Object.assign(user, await hashPassword(req.body.password));
    for (const [token, session] of sessions) if (session.userId === user.id) sessions.delete(token);
  }
  writeJson(USERS_FILE, users);
  const changes = [];
  if (previous.role !== user.role) changes.push(`角色设为${user.role === 'admin' ? '管理员' : '成员'}`);
  if (previous.active !== user.active) changes.push(user.active ? '启用账号' : '停用账号');
  if (previous.quotaBytes !== user.quotaBytes) changes.push(`容量调整为 ${(user.quotaBytes / (1024 ** 3)).toFixed(1)} GB`);
  if (typeof req.body?.password === 'string') changes.push('重设密码');
  recordAudit(req, 'member.updated', `${user.username}：${changes.join('、') || '更新成员信息'}`);
  res.json({ success: true });
});

app.get('/api/files', auth, (req, res) => {
  const scope = req.query.scope === 'private' ? 'private' : 'team';
  const searchQuery = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 120).toLocaleLowerCase('zh-CN') : '';
  const favoritesOnly = req.query.favorites === 'true';
  const sortBy = ['name', 'size', 'mtime'].includes(req.query.sort_by) ? req.query.sort_by : 'mtime';
  const sortOrder = req.query.sort_order === 'asc' ? 1 : -1;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(req.query.per_page, 10) || 20));
  let rows = Object.values(fileRecords).filter(record => (favoritesOnly
    ? Array.isArray(record.favoritedBy) && record.favoritedBy.includes(req.user.id)
    : record.scope === scope) && canRead(req, record)
    && (!searchQuery || String(record.name).toLocaleLowerCase('zh-CN').includes(searchQuery)));
  rows = rows.map(record => {
    const ext = path.extname(record.name).toLowerCase();
    let type = 'other';
    if (['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'].includes(ext)) type = 'image';
    else if (['.txt', '.md', '.json', '.csv', '.xml', '.yaml', '.yml', '.log', '.js', '.py', '.html', '.css', '.conf', '.ini', '.cfg'].includes(ext)) type = 'text';
    else if (['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'].includes(ext)) type = 'document';
    return { ...record, sizeText: formatSize(record.size), type, ext, isFavorite: Array.isArray(record.favoritedBy) && record.favoritedBy.includes(req.user.id), canDelete: canChange(req, record), owner: users.find(row => row.id === record.ownerId)?.username || '已停用成员' };
  });
  rows.sort((a, b) => {
    const cmp = sortBy === 'name' ? a.name.localeCompare(b.name, 'zh-CN') : sortBy === 'size' ? a.size - b.size : a.mtime - b.mtime;
    return cmp * sortOrder;
  });
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const actualPage = Math.min(page, totalPages);
  res.json({ files: rows.slice((actualPage - 1) * perPage, actualPage * perPage), total, page: actualPage, totalPages, perPage });
});

app.patch('/api/files/:name/favorite', auth, (req, res) => {
  const record = getRecord(req.params.name);
  if (!record || !fs.existsSync(getFilePath(record.name))) return res.status(404).json({ error: '文件不存在' });
  if (!canRead(req, record)) return res.status(403).json({ error: '没有权限收藏此文件' });
  if (typeof req.body?.favorite !== 'boolean') return res.status(400).json({ error: '收藏状态无效' });
  const favoritedBy = new Set(Array.isArray(record.favoritedBy) ? record.favoritedBy : []);
  if (req.body.favorite) favoritedBy.add(req.user.id);
  else favoritedBy.delete(req.user.id);
  if (favoritedBy.size) record.favoritedBy = [...favoritedBy];
  else delete record.favoritedBy;
  persistFiles();
  recordAudit(req, req.body.favorite ? 'file.favorited' : 'file.unfavorited', record.name);
  res.json({ success: true, isFavorite: req.body.favorite });
});

app.post('/api/upload', auth, (req, res) => {
  upload.single('file')(req, res, error => {
    if (error) return res.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: error.code === 'LIMIT_FILE_SIZE' ? '单文件不能超过 200 MB' : error.message });
    if (!req.file) return res.status(400).json({ error: '请选择文件' });
    const originalName = safeName(req.file.originalname);
    const name = uniqueName(originalName);
    const finalPath = getFilePath(name);
    const usedBytes = getUserUsageBytes(req.user.id);
    const remainingBytes = Math.max(0, req.user.quotaBytes - usedBytes);
    if (req.file.size > remainingBytes) {
      fs.rmSync(req.file.path, { force: true });
      return res.status(409).json({ error: `容量不足：当前已用 ${formatSize(usedBytes)}，可用 ${formatSize(remainingBytes)}`, quotaExceeded: true, usedBytes, quotaBytes: req.user.quotaBytes, remainingBytes });
    }
    try {
      fs.renameSync(req.file.path, finalPath);
      const stat = fs.statSync(finalPath);
      const scope = req.body?.scope === 'private' ? 'private' : 'team';
      fileRecords[name] = { name, size: stat.size, mtime: stat.mtimeMs, scope, ownerId: req.user.id, note: '' };
      persistFiles();
      recordAudit(req, 'file.uploaded', `${name}（${scope === 'private' ? '个人文件' : '团队共享'}，${formatSize(stat.size)}）`);
      res.json({ success: true, name });
    } catch (saveError) {
      delete fileRecords[name];
      fs.rmSync(req.file.path, { force: true });
      fs.rmSync(finalPath, { force: true });
      res.status(500).json({ error: '保存文件失败' });
    }
  });
});
function resolveAccessible(req, res, name, writable = false) {
  const record = getRecord(name);
  if (!record || !fs.existsSync(getFilePath(name))) { res.status(404).json({ error: '文件不存在' }); return null; }
  if (!(writable ? canChange(req, record) : canRead(req, record))) { res.status(403).json({ error: '没有权限访问此文件' }); return null; }
  return record;
}
app.post('/api/files/:name/share', auth, async (req, res) => {
  const record = resolveAccessible(req, res, req.params.name);
  if (!record) return;
  const hours = req.body?.hours === undefined ? 24 : Number(req.body.hours);
  if (!Number.isSafeInteger(hours) || hours < 1 || hours > 720) return res.status(400).json({ error: '有效期需为 1–720 小时' });
  cleanupExpiredShares();
  if (Object.keys(fileShares).length >= 1000) return res.status(503).json({ error: '当前分享链接数量已达上限，请稍后再试' });
  const token = randomId(32);
  const code = makeShareCode();
  const shareId = shareTokenDigest(token);
  const credentials = await hashPassword(code);
  const createdAt = Date.now();
  fileShares[shareId] = {
    name: record.name,
    createdBy: req.user.id,
    createdAt,
    expiresAt: createdAt + hours * 60 * 60 * 1000,
    ...credentials,
  };
  persistShares();
  recordAudit(req, 'share.created', `${record.name}，有效 ${hours} 小时`);
  res.status(201).json({ success: true, token, code, expiresAt: fileShares[shareId].expiresAt });
});
app.post('/api/share/:token/verify', async (req, res) => {
  const token = String(req.params.token || '');
  if (!/^[a-f0-9]{64}$/i.test(token)) return res.status(404).json({ error: '分享链接无效或已失效' });
  const shareId = shareTokenDigest(token);
  const share = fileShares[shareId];
  if (!share) return res.status(404).json({ error: '分享链接无效或已失效' });
  if (share.expiresAt <= Date.now()) {
    delete fileShares[shareId];
    persistShares();
    return res.status(410).json({ error: '分享链接已过期' });
  }
  const attemptKey = `${shareId}:${getClientIP(req)}`;
  const previous = shareCodeAttempts.get(attemptKey);
  if (previous && previous.until > Date.now() && previous.count >= 5) return res.status(429).json({ error: '提取码尝试次数过多，请 15 分钟后重试' });
  const code = typeof req.body?.code === 'string' ? req.body.code.trim().replace(/\s+/g, '').toUpperCase() : '';
  const valid = code.length <= 16 && await passwordMatches(code, share);
  if (!valid) {
    const current = previous && previous.until > Date.now() ? previous : { count: 0, until: Date.now() + 15 * 60 * 1000 };
    current.count++;
    shareCodeAttempts.set(attemptKey, current);
    cleanupShareRuntimeState();
    if (current.count === 5) recordAudit(req, 'share.code_blocked', `提取码尝试超限：${share.name}`);
    return res.status(current.count >= 5 ? 429 : 401).json({ error: current.count >= 5 ? '提取码尝试次数过多，请 15 分钟后重试' : '提取码不正确，请检查后重试' });
  }
  shareCodeAttempts.delete(attemptKey);
  const record = getRecord(share.name);
  if (!record || !fs.existsSync(getFilePath(share.name))) return res.status(410).json({ error: '分享文件已不存在' });
  const grant = randomId(24);
  shareDownloadGrants.set(grant, { shareId, expiresAt: Math.min(share.expiresAt, Date.now() + 2 * 60 * 1000) });
  cleanupShareRuntimeState();
  res.set('Cache-Control', 'no-store, max-age=0');
  res.json({ success: true, grant });
});
app.get('/api/shared-download/:grant', (req, res) => {
  const grantId = String(req.params.grant || '');
  const grant = shareDownloadGrants.get(grantId);
  if (!grant || grant.expiresAt <= Date.now()) {
    shareDownloadGrants.delete(grantId);
    return res.status(410).send('下载授权已过期，请返回分享页面重新输入提取码。');
  }
  shareDownloadGrants.delete(grantId);
  const share = fileShares[grant.shareId];
  if (!share || share.expiresAt <= Date.now()) return res.status(410).send('分享链接已过期。');
  if (!fs.existsSync(getFilePath(share.name))) return res.status(410).send('分享文件已不存在。');
  recordAudit(req, 'share.downloaded', share.name);
  res.set('Cache-Control', 'no-store, max-age=0');
  res.download(getFilePath(share.name), share.name);
});
app.delete('/api/share/:token', auth, (req, res) => {
  const token = String(req.params.token || '');
  if (!/^[a-f0-9]{64}$/i.test(token)) return res.status(404).json({ error: '分享链接不存在' });
  const shareId = shareTokenDigest(token);
  const share = fileShares[shareId];
  if (!share) return res.status(404).json({ error: '分享链接不存在或已过期' });
  const record = getRecord(share.name);
  if (!record || !(share.createdBy === req.user.id || canChange(req, record))) return res.status(403).json({ error: '没有权限撤销此分享链接' });
  delete fileShares[shareId];
  persistShares();
  for (const [grantId, grant] of shareDownloadGrants) if (grant.shareId === shareId) shareDownloadGrants.delete(grantId);
  recordAudit(req, 'share.revoked', share.name);
  res.json({ success: true });
});
app.get('/api/download/:name', auth, (req, res) => {
  const record = resolveAccessible(req, res, req.params.name);
  if (record) { recordAudit(req, 'file.downloaded', record.name); res.download(getFilePath(record.name), record.name); }
});
app.get('/api/preview/:name', auth, (req, res) => {
  const record = resolveAccessible(req, res, req.params.name);
  if (!record) return;
  recordAudit(req, 'file.previewed', record.name);
  const ext = path.extname(record.name).toLowerCase();
  const textExts = ['.txt', '.md', '.json', '.csv', '.xml', '.yaml', '.yml', '.log', '.js', '.py', '.html', '.css', '.conf', '.ini', '.cfg'];
  if (textExts.includes(ext)) {
    const fd = fs.openSync(getFilePath(record.name), 'r');
    const buffer = Buffer.alloc(50000);
    let bytesRead = 0;
    try { bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0); } finally { fs.closeSync(fd); }
    return res.json({ type: 'text', content: buffer.subarray(0, bytesRead).toString('utf8') });
  }
  if (['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'].includes(ext)) return res.json({ type: 'image', url: `/api/download/${encodeURIComponent(record.name)}` });
  res.json({ type: 'unsupported', message: '不支持预览此格式' });
});
app.delete('/api/delete/:name', auth, (req, res) => {
  const record = resolveAccessible(req, res, req.params.name, true);
  if (!record) return;
  fs.rmSync(getFilePath(record.name), { force: true });
  delete fileRecords[record.name];
  persistFiles();
  recordAudit(req, 'file.deleted', record.name);
  res.json({ success: true });
});
app.post('/api/batch-delete', auth, (req, res) => {
  const names = req.body?.names;
  if (!Array.isArray(names) || !names.length || names.length > 100) return res.status(400).json({ error: '请选择 1–100 个文件' });
  const results = { success: [], failed: [] };
  for (const name of names) {
    const record = getRecord(name);
    if (!record || !fs.existsSync(getFilePath(name))) results.failed.push({ name, error: '文件不存在' });
    else if (!canChange(req, record)) results.failed.push({ name, error: '没有删除权限' });
    else {
      try { fs.rmSync(getFilePath(name)); delete fileRecords[name]; results.success.push(name); }
      catch { results.failed.push({ name, error: '删除失败' }); }
    }
  }
  persistFiles();
  if (results.success.length) recordAudit(req, 'file.batch_deleted', results.success.join('、'));
  res.json(results);
});
app.post('/api/batch-download', auth, async (req, res) => {
  const names = req.body?.names;
  if (!Array.isArray(names) || !names.length || names.length > 100) return res.status(400).json({ error: '请选择 1–100 个文件' });
  const records = names.map(getRecord).filter(record => record && canRead(req, record) && fs.existsSync(getFilePath(record.name)));
  if (!records.length) return res.status(404).json({ error: '没有找到可下载的文件' });
  const archiver = require('archiver');
  const archive = archiver('zip', { zlib: { level: 1 } });
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent('批量下载.zip')}`);
  recordAudit(req, 'file.batch_downloaded', records.map(record => record.name).join('、'));
  archive.on('error', () => { if (!res.headersSent) res.status(500); res.end(); });
  archive.pipe(res);
  for (const record of records) archive.file(getFilePath(record.name), { name: record.name });
  archive.finalize();
});
app.post('/api/notes/:name', auth, (req, res) => {
  const record = resolveAccessible(req, res, req.params.name, true);
  if (!record) return;
  record.note = typeof req.body?.note === 'string' ? req.body.note.trim().slice(0, 500) : '';
  persistFiles();
  recordAudit(req, 'file.note_updated', record.name);
  res.json({ success: true });
});

app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/s/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'share.html')));
app.use((error, req, res, next) => {
  console.error('Request failed:', error.message);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: '服务器处理失败' });
});

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
app.listen(PORT, '0.0.0.0', () => console.log(`轻量团队云盘监听端口 ${PORT}（账号上限 ${MAX_USERS}）`));
