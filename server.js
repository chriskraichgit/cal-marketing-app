const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');
const { URL } = require('url');

function htmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const PORT = 5000;
const HOST = '0.0.0.0';

const TOKEN_FILE = path.join(__dirname, '.gdrive-tokens.json');
const GOOGLE_TOKEN_FILE = path.join(__dirname, '.google-tokens.json');
const META_STORE_FILE = path.join(__dirname, '.cal-meta-store.json');

// ── Place IDs per account (no OAuth needed — uses Places API) ──
const ACCOUNT_PLACE_IDS = {
  'info@unitedsewerservice.com': { placeId: 'ChIJvX0LSNPQ3IkRdma8QADGAhY', name: 'United Sewer and Septic' },
  'greencollар': { placeId: 'ChIJJ8-biosyw4kR738ilrfxrbU', name: 'Green Collar Roofing & Exteriors' },
  'willydiamond': { placeId: 'ChIJqcP1Ry7XwokRmaR_t8kedZM', name: 'Willy Diamond Property Management' },
};

// ── Per-account feature flags ──
const ACCOUNT_FEATURES = {
  'info@unitedsewerservice.com': { nfc: true, reviews: true, drive: false, calendar: false, stripe: false, searchConsole: false, placeId: 'ChIJvX0LSNPQ3IkRdma8QADGAhY' },
  'greencollаr':                 { nfc: true, reviews: true, drive: false, calendar: false, stripe: false, searchConsole: false, placeId: 'ChIJJ8-biosyw4kR738ilrfxrbU' },
  'willydiamond':                { nfc: true, reviews: true, drive: false, calendar: false, stripe: false, searchConsole: false, placeId: 'ChIJqcP1Ry7XwokRmaR_t8kedZM' },
};
const DEFAULT_FEATURES = { nfc: true, reviews: true, drive: true, calendar: true, stripe: true, searchConsole: true };

// Known users for server-side meta token issuance.
// Passwords are stored as SHA-256 hashes only — never plaintext.
// Agency/test roles may access any account key; admin/user roles may only access their own email key.
const SERVER_USERS = {
  'chris@cal.marketing':           { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'superadmin', calRole: 'superadmin', accounts: ['info@unitedsewerservice.com','greencollаr','willydiamond'] },
  'james@cal.marketing':           { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'superadmin', calRole: 'superadmin', accounts: ['info@unitedsewerservice.com','greencollаr','willydiamond'] },
  'matt@cal.marketing':            { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'superadmin', calRole: 'superadmin', accounts: ['info@unitedsewerservice.com','greencollаr','willydiamond'] },
  'info@cal.marketing':            { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'test',       calRole: 'superadmin', accounts: ['info@unitedsewerservice.com','greencollаr','willydiamond'] },
  'client@apexlegal.com':          { pwHash: '7e166f079a275064a2118127d7102a9471f671acb67a65a2c628684606b5e11f', role: 'admin',       calRole: 'client',     accounts: ['client@apexlegal.com'] },
  'staff@apexlegal.com':           { pwHash: '7df64b2903b0ac2dc591ee097c36f4acdae759753bd197eaf11008093e2966ca', role: 'user',        calRole: 'client',     accounts: ['client@apexlegal.com'] },
  'info@unitedsewerservice.com':   { pwHash: 'c87b71ef7b9882f404028ae7d5431cc6fdb73b64cfe52e9dc0501ff3dbe1a580', role: 'admin',       calRole: 'client',     accounts: ['info@unitedsewerservice.com'] },
};

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days (non-driver)
const DRIVER_TOKEN_TTL_MS = 365 * 24 * 60 * 60 * 1000; // 1 year for drivers

// Secret is sourced from the environment (set CAL_META_SECRET in production for persistence).
// If absent, a random ephemeral secret is generated at startup — tokens will not survive a restart.
const META_SECRET = process.env.CAL_META_SECRET || crypto.randomBytes(32).toString('hex');

function signMetaToken(payload) {
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', META_SECRET).update(b64).digest('base64url');
  return b64 + '.' + sig;
}

function verifyMetaToken(token) {
  try {
    const dot = token.indexOf('.');
    if (dot === -1) return null;
    const b64 = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', META_SECRET).update(b64).digest('base64url');
    const eBuf = Buffer.from(expected);
    const sBuf = Buffer.from(sig);
    if (eBuf.length !== sBuf.length || !crypto.timingSafeEqual(eBuf, sBuf)) return null;
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (!payload || Date.now() > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}

function isKeyAllowed(key, payload) {
  if (payload.role === 'agency' || payload.role === 'test' || payload.role === 'superadmin' || payload.calRole === 'superadmin') return true;
  return key === payload.email;
}

function extractBearerToken(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : null;
}

function getRedirectUri() {
  const domain = process.env.REPLIT_DEV_DOMAIN || process.env.REPLIT_DOMAINS || `localhost:${PORT}`;
  const host = domain.split(',')[0].trim();
  return `https://${host}/api/drive/callback`;
}

function createOAuth2Client() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return new google.auth.OAuth2(clientId, clientSecret, getRedirectUri());
}

function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    }
  } catch (e) {}
  return null;
}

function saveTokens(tokens) {
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2));
}

function deleteTokens() {
  try { if (fs.existsSync(TOKEN_FILE)) fs.unlinkSync(TOKEN_FILE); } catch (e) {}
}

function loadMetaStore() {
  try {
    if (fs.existsSync(META_STORE_FILE)) return JSON.parse(fs.readFileSync(META_STORE_FILE, 'utf8'));
  } catch (e) {}
  return {};
}

function saveMetaStore(store) {
  try { fs.writeFileSync(META_STORE_FILE, JSON.stringify(store)); } catch (e) {}
}

// ── Write queue (prevents concurrent write corruption) ──
var _writeQueue = Promise.resolve();
function saveMetaStoreQueued(store) {
  _writeQueue = _writeQueue.then(function() {
    try { fs.writeFileSync(META_STORE_FILE, JSON.stringify(store, null, 2)); } catch(e) { console.error('store write error', e); }
  });
  return _writeQueue;
}

// ── Login rate limiting ──
const _loginAttempts = {};
function checkLoginRateLimit(email) {
  const now = Date.now();
  const rec = _loginAttempts[email] || { count: 0, lockedUntil: 0 };
  if (rec.lockedUntil > now) return { locked: true, remaining: Math.ceil((rec.lockedUntil - now) / 1000) };
  return { locked: false };
}
function recordLoginFailure(email) {
  const rec = _loginAttempts[email] || { count: 0, lockedUntil: 0 };
  rec.count++;
  if (rec.count >= 5) { rec.lockedUntil = Date.now() + 15 * 60 * 1000; rec.count = 0; }
  _loginAttempts[email] = rec;
}
function clearLoginAttempts(email) { delete _loginAttempts[email]; }

// ── Simple password hash (SHA-256) ──
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// ── Helper: metaGet ──
function metaGet(key) {
  const store = loadMetaStore();
  return store[key] !== undefined ? store[key] : null;
}

async function handleMetaLogin(req, res) {
  let body;
  try {
    const raw = await readRequestBody(req, 64 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }

  const email = (body && typeof body.email === 'string') ? body.email.trim().toLowerCase() : '';
  const password = (body && typeof body.password === 'string') ? body.password : '';

  // Rate limiting check
  const rateCheck = checkLoginRateLimit(email);
  if (rateCheck.locked) {
    jsonResponse(res, 429, { error: 'TOO_MANY_ATTEMPTS', remaining: rateCheck.remaining });
    return;
  }

  // Check SERVER_USERS first
  const staticUser = SERVER_USERS[email];
  if (staticUser) {
    const submittedHash = crypto.createHash('sha256').update(password).digest('hex');
    const hashBuf = Buffer.from(staticUser.pwHash, 'hex');
    const submitBuf = Buffer.from(submittedHash, 'hex');
    if (hashBuf.length !== submitBuf.length || !crypto.timingSafeEqual(hashBuf, submitBuf)) {
      recordLoginFailure(email);
      jsonResponse(res, 401, { error: 'INVALID_CREDENTIALS' }); return;
    }
    clearLoginAttempts(email);
    const calRole = staticUser.calRole || 'client';
    const accounts = staticUser.accounts || [email];
    const displayName = staticUser.displayName || email.split('@')[0];
    const payload = { email, role: staticUser.role, calRole, accounts, displayName, driverName: null, exp: Date.now() + TOKEN_TTL_MS };
    const token = signMetaToken(payload);
    jsonResponse(res, 200, { token, email, calRole, role: staticUser.role, accounts, displayName, driverName: null });
    return;
  }

  // Check dynamic _users in meta store (clients and drivers)
  const store = loadMetaStore();
  const dynUsers = store['_users'] || {};
  const dynUser = dynUsers[email];
  if (!dynUser) {
    recordLoginFailure(email);
    jsonResponse(res, 401, { error: 'INVALID_CREDENTIALS' }); return;
  }
  const submittedHash = crypto.createHash('sha256').update(password).digest('hex');
  if (dynUser.passwordHash !== submittedHash) {
    recordLoginFailure(email);
    jsonResponse(res, 401, { error: 'INVALID_CREDENTIALS' }); return;
  }
  clearLoginAttempts(email);
  const calRole = dynUser.role || 'client';
  const accounts = dynUser.accounts || [email];
  const displayName = dynUser.displayName || dynUser.driverName || email.split('@')[0];
  const driverName = dynUser.driverName || null;
  const ttl = calRole === 'driver' ? DRIVER_TOKEN_TTL_MS : TOKEN_TTL_MS;
  const payload = { email, role: calRole, calRole, accounts, displayName, driverName, exp: Date.now() + ttl };
  const token = signMetaToken(payload);
  jsonResponse(res, 200, { token, email, calRole, role: calRole, accounts, displayName, driverName });
}

async function handleMetaGet(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const key = qs.key;
  if (!key) { jsonResponse(res, 400, { error: 'MISSING_KEY' }); return; }
  if (!isKeyAllowed(key, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
  const store = loadMetaStore();
  jsonResponse(res, 200, { meta: store[key] || null });
}

async function handleMetaPut(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const key = qs.key;
  if (!key) { jsonResponse(res, 400, { error: 'MISSING_KEY' }); return; }
  if (!isKeyAllowed(key, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
  let body;
  try {
    const raw = await readRequestBody(req, 2 * 1024 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  if (!body || typeof body !== 'object' || Array.isArray(body)) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  const store = loadMetaStore();
  store[key] = Object.assign({}, store[key] || {}, body);
  saveMetaStoreQueued(store);
  jsonResponse(res, 200, { ok: true });
}

function getAuthedClient() {
  const oauth2 = createOAuth2Client();
  if (!oauth2) return null;
  const tokens = loadTokens();
  if (!tokens) return null;
  oauth2.setCredentials(tokens);
  oauth2.on('tokens', (newTokens) => {
    const current = loadTokens() || {};
    saveTokens(Object.assign({}, current, newTokens));
  });
  return oauth2;
}

function mimeIcon(mimeType) {
  if (!mimeType) return 'file';
  if (mimeType === 'application/vnd.google-apps.folder') return 'folder';
  if (mimeType.startsWith('image/')) return 'image';
  if (mimeType.startsWith('video/')) return 'video';
  if (mimeType === 'application/pdf') return 'pdf';
  if (mimeType.includes('spreadsheet') || mimeType.includes('excel')) return 'sheet';
  if (mimeType.includes('presentation') || mimeType.includes('powerpoint')) return 'slide';
  if (mimeType.includes('document') || mimeType.includes('word')) return 'doc';
  return 'file';
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return null;
  const n = parseInt(bytes);
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function parseQueryString(url) {
  try {
    const idx = url.indexOf('?');
    if (idx === -1) return {};
    const pairs = url.slice(idx + 1).split('&');
    const out = {};
    for (const p of pairs) {
      const eq = p.indexOf('=');
      if (eq === -1) continue;
      const k = decodeURIComponent(p.slice(0, eq));
      const v = decodeURIComponent(p.slice(eq + 1));
      out[k] = v;
    }
    return out;
  } catch (e) { return {}; }
}

// ── Resend email helper ──
async function sendEmail({ to, subject, html }) {
  const RESEND_API_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_API_KEY) {
    console.warn('[email] RESEND_API_KEY not set — skipping email to', to);
    return { ok: false, reason: 'NO_API_KEY' };
  }
  return new Promise((resolve) => {
    const body = JSON.stringify({
      from: 'CAL OS <noreply@cal.marketing>',
      to: [to],
      subject,
      html
    });
    const opts = {
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const r = require('https').request(opts, (res2) => {
      let d = '';
      res2.on('data', c => d += c);
      res2.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          if (res2.statusCode >= 200 && res2.statusCode < 300) {
            resolve({ ok: true, id: parsed.id });
          } else {
            console.error('[email] Resend error', res2.statusCode, d);
            resolve({ ok: false, reason: d });
          }
        } catch(e) { resolve({ ok: false, reason: 'PARSE_ERROR' }); }
      });
    });
    r.on('error', (e) => { console.error('[email] request error', e); resolve({ ok: false, reason: e.message }); });
    r.write(body);
    r.end();
  });
}

// ── Magic Link: Request ──
// POST /api/auth/magic-link  { email }
async function handleMagicLinkRequest(req, res) {
  let body;
  try {
    const raw = await readRequestBody(req, 16 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { return jsonResponse(res, 400, { error: 'INVALID_BODY' }); }

  const email = (body && typeof body.email === 'string') ? body.email.trim().toLowerCase() : '';
  if (!email) return jsonResponse(res, 400, { error: 'MISSING_EMAIL' });

  // Only allow known users (dynamic _users — mainly drivers)
  const store = loadMetaStore();
  const dynUsers = store['_users'] || {};
  const user = dynUsers[email];
  // Also allow SERVER_USERS (superadmin/client)
  const staticUser = SERVER_USERS[email];
  if (!user && !staticUser) {
    // Always return OK to prevent user enumeration
    return jsonResponse(res, 200, { ok: true });
  }

  // Generate a one-time token (32 random bytes, 15-min TTL)
  const token = crypto.randomBytes(32).toString('hex');
  const magicLinks = store['_magicLinks'] || {};
  magicLinks[token] = {
    email,
    exp: Date.now() + 15 * 60 * 1000,
    used: false
  };
  store['_magicLinks'] = magicLinks;
  saveMetaStoreQueued(store);

  // Determine the app base URL
  const host = process.env.REPLIT_DEPLOYMENT_URL
    || process.env.APP_BASE_URL
    || `https://${process.env.REPLIT_DEV_DOMAIN || 'your-app.replit.app'}`;
  const link = `${host}/api/auth/verify?token=${token}`;

  const displayName = (user && (user.displayName || user.driverName)) || (staticUser && staticUser.displayName) || email.split('@')[0];
  await sendEmail({
    to: email,
    subject: 'Your CAL OS sign-in link',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#fff">
        <img src="https://assets.cdn.filesafe.space/CWA7ybFILove8e29NqFc/media/6a381eca1c5d711b35cfdfbb.png"
             alt="CAL Marketing" style="height:40px;margin-bottom:24px;display:block">
        <h2 style="font-size:22px;font-weight:900;color:#111;margin:0 0 8px">Sign in to CAL OS</h2>
        <p style="font-size:15px;color:#555;margin:0 0 28px">Hey ${displayName}, click the button below to sign in. This link expires in 15 minutes and can only be used once.</p>
        <a href="${link}" style="display:inline-block;background:#C9A84C;color:#000;font-weight:900;font-size:16px;padding:14px 32px;border-radius:10px;text-decoration:none;letter-spacing:.02em">Sign In to CAL OS →</a>
        <p style="font-size:12px;color:#999;margin:28px 0 0">If you didn't request this, you can safely ignore it. This link will expire on its own.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="font-size:11px;color:#bbb;margin:0">CAL Marketing · Client Operating System</p>
      </div>
    `
  });

  return jsonResponse(res, 200, { ok: true });
}

// ── Magic Link: Verify ──
// GET /api/auth/verify?token=xxx
async function handleMagicLinkVerify(req, res, qs) {
  const token = (qs.token || '').trim();
  if (!token) return jsonResponse(res, 400, { error: 'MISSING_TOKEN' });

  const store = loadMetaStore();
  const magicLinks = store['_magicLinks'] || {};
  const link = magicLinks[token];

  if (!link) return sendHtmlError(res, 'Invalid or expired sign-in link.');
  if (link.used) return sendHtmlError(res, 'This sign-in link has already been used.');
  if (Date.now() > link.exp) {
    delete magicLinks[token];
    store['_magicLinks'] = magicLinks;
    saveMetaStoreQueued(store);
    return sendHtmlError(res, 'This sign-in link has expired. Please request a new one.');
  }

  // Mark used
  link.used = true;
  store['_magicLinks'] = magicLinks;
  saveMetaStoreQueued(store);

  const email = link.email;
  // Look up user to build token payload
  const dynUsers = store['_users'] || {};
  const user = dynUsers[email] || SERVER_USERS[email];
  if (!user) return sendHtmlError(res, 'Account not found.');

  const calRole = user.calRole || user.role || 'client';
  const accounts = user.accounts || [email];
  const displayName = user.displayName || user.driverName || email.split('@')[0];
  const driverName = user.driverName || null;
  const ttl = calRole === 'driver' ? DRIVER_TOKEN_TTL_MS : TOKEN_TTL_MS;
  const payload = { email, role: calRole, calRole, accounts, displayName, driverName, exp: Date.now() + ttl };
  const sessionToken = signMetaToken(payload);

  // Redirect to app with token in hash — the SPA picks it up
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signing you in…</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:80px;background:#0a0a0a;color:#fff">
<p style="font-size:18px;font-weight:700">Signing you in…</p>
<script>
try { localStorage.setItem('cal-meta-session-token', ${JSON.stringify(sessionToken)}); } catch(e){}
try { localStorage.setItem('cal-user-role', ${JSON.stringify(calRole)}); } catch(e){}
try { localStorage.setItem('cal-driver-name', ${JSON.stringify(driverName || '')}); } catch(e){}
try { localStorage.setItem('cal-display-name', ${JSON.stringify(displayName)}); } catch(e){}
try { localStorage.setItem('cal-current-acct', ${JSON.stringify(accounts[0] || '')}); } catch(e){}
window.location.replace('/');
</script>
</body></html>`;
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendHtmlError(res, msg) {
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sign-in Error</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:80px;background:#0a0a0a;color:#fff">
<p style="font-size:20px;font-weight:900;color:#e53935">Sign-in Error</p>
<p style="font-size:15px;color:#aaa;margin:12px 0 32px">${msg}</p>
<a href="/" style="color:#C9A84C;font-weight:700;text-decoration:none">← Back to Login</a>
</body></html>`;
  res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

// ── Create Client Account (superadmin only) ──
async function handleCreateClient(req, res, payload) {
  if (payload.role !== 'superadmin' && payload.calRole !== 'superadmin') {
    return jsonResponse(res, 403, { error: 'FORBIDDEN' });
  }
  let body;
  try {
    const raw = await readRequestBody(req, 32 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { return jsonResponse(res, 400, { error: 'INVALID_BODY' }); }
  const { email, password, displayName, accounts } = body || {};
  if (!email || !password) return jsonResponse(res, 400, { error: 'MISSING_FIELDS' });
  const store = loadMetaStore();
  const users = store['_users'] || {};
  if (users[email.toLowerCase()] || SERVER_USERS[email.toLowerCase()]) {
    return jsonResponse(res, 409, { error: 'USER_EXISTS' });
  }
  const passwordHash = hashPassword(password);
  users[email.toLowerCase()] = {
    email: email.toLowerCase(),
    passwordHash,
    accounts: Array.isArray(accounts) && accounts.length ? accounts : [email.toLowerCase()],
    displayName: displayName || email.split('@')[0],
    role: 'client',
    calRole: 'client',
    driverName: null,
    createdAt: new Date().toISOString()
  };
  store['_users'] = users;
  saveMetaStoreQueued(store);
  return jsonResponse(res, 200, { ok: true, email: email.toLowerCase(), role: 'client' });
}

// ── List Users (superadmin only) ──
async function handleListUsers(req, res, payload) {
  if (payload.role !== 'superadmin' && payload.calRole !== 'superadmin') {
    return jsonResponse(res, 403, { error: 'FORBIDDEN' });
  }
  const store = loadMetaStore();
  const dynUsers = store['_users'] || {};
  const list = Object.values(dynUsers).map(u => ({
    email: u.email,
    displayName: u.displayName,
    driverName: u.driverName || null,
    role: u.calRole || u.role,
    accounts: u.accounts,
    createdAt: u.createdAt
  }));
  return jsonResponse(res, 200, { users: list });
}

// ── Delete User (superadmin only) ──
async function handleDeleteUser(req, res, payload) {
  if (payload.role !== 'superadmin' && payload.calRole !== 'superadmin') {
    return jsonResponse(res, 403, { error: 'FORBIDDEN' });
  }
  let body;
  try {
    const raw = await readRequestBody(req, 8 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { return jsonResponse(res, 400, { error: 'INVALID_BODY' }); }
  const email = (body && body.email) ? body.email.toLowerCase() : '';
  if (!email) return jsonResponse(res, 400, { error: 'MISSING_EMAIL' });
  const store = loadMetaStore();
  const users = store['_users'] || {};
  if (!users[email]) return jsonResponse(res, 404, { error: 'USER_NOT_FOUND' });
  delete users[email];
  store['_users'] = users;
  saveMetaStoreQueued(store);
  return jsonResponse(res, 200, { ok: true });
}

// ── Send Onboarding Email (superadmin: after creating user) ──
async function handleSendOnboardingEmail(req, res, payload) {
  if (payload.role !== 'superadmin' && payload.calRole !== 'superadmin') {
    return jsonResponse(res, 403, { error: 'FORBIDDEN' });
  }
  let body;
  try {
    const raw = await readRequestBody(req, 16 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { return jsonResponse(res, 400, { error: 'INVALID_BODY' }); }
  const { email, password, role: userRole, displayName } = body || {};
  if (!email) return jsonResponse(res, 400, { error: 'MISSING_EMAIL' });

  const host = process.env.REPLIT_DEPLOYMENT_URL
    || process.env.APP_BASE_URL
    || `https://${process.env.REPLIT_DEV_DOMAIN || 'your-app.replit.app'}`;

  const isDriver = userRole === 'driver';
  const subject = isDriver
    ? `You're invited to CAL OS — ${displayName || 'your account is ready'}`
    : `Your CAL OS account is ready`;

  const html = `
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#fff">
      <img src="https://assets.cdn.filesafe.space/CWA7ybFILove8e29NqFc/media/6a381eca1c5d711b35cfdfbb.png"
           alt="CAL Marketing" style="height:40px;margin-bottom:24px;display:block">
      <h2 style="font-size:22px;font-weight:900;color:#111;margin:0 0 8px">Welcome to CAL OS</h2>
      <p style="font-size:15px;color:#555;margin:0 0 20px">Hey ${displayName || email.split('@')[0]}, your ${isDriver ? 'driver' : 'client'} account has been created.</p>
      <div style="background:#f9f9f9;border-radius:10px;padding:20px;margin-bottom:24px">
        <p style="margin:0 0 8px;font-size:13px;color:#555"><strong>Login URL:</strong> <a href="${host}" style="color:#C9A84C">${host}</a></p>
        <p style="margin:0 0 8px;font-size:13px;color:#555"><strong>Email:</strong> ${email}</p>
        ${password ? `<p style="margin:0;font-size:13px;color:#555"><strong>Temporary password:</strong> ${password}</p>` : ''}
      </div>
      <a href="${host}" style="display:inline-block;background:#C9A84C;color:#000;font-weight:900;font-size:16px;padding:14px 32px;border-radius:10px;text-decoration:none">Sign In to CAL OS →</a>
      <p style="font-size:12px;color:#999;margin:28px 0 0">If you have any issues logging in, reply to this email or contact your account manager.</p>
    </div>
  `;

  const result = await sendEmail({ to: email, subject, html });
  return jsonResponse(res, 200, { ok: result.ok, reason: result.reason || null });
}

// ── Create Driver Account (superadmin only) ──
async function handleCreateDriver(req, res, payload) {
  if (payload.role !== 'superadmin' && payload.calRole !== 'superadmin') {
    return jsonResponse(res, 403, { error: 'FORBIDDEN' });
  }
  let body;
  try {
    const raw = await readRequestBody(req, 32 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { return jsonResponse(res, 400, { error: 'INVALID_BODY' }); }
  const { email, password, displayName, account, driverName } = body || {};
  if (!email || !password || !account || !driverName) {
    return jsonResponse(res, 400, { error: 'MISSING_FIELDS' });
  }
  const store = loadMetaStore();
  const users = store['_users'] || {};
  if (users[email.toLowerCase()]) {
    return jsonResponse(res, 409, { error: 'USER_EXISTS' });
  }
  const passwordHash = hashPassword(password);
  users[email.toLowerCase()] = {
    email: email.toLowerCase(),
    passwordHash,
    accounts: [account],
    displayName: displayName || driverName,
    role: 'driver',
    calRole: 'driver',
    driverName,
    createdAt: new Date().toISOString()
  };
  store['_users'] = users;
  saveMetaStoreQueued(store);
  return jsonResponse(res, 200, { ok: true, email: email.toLowerCase(), role: 'driver' });
}

// ── My Driver Stats (driver role only) ──
async function handleMyDriverStats(req, res, payload) {
  if (payload.role !== 'driver' && payload.calRole !== 'driver') {
    return jsonResponse(res, 403, { error: 'FORBIDDEN' });
  }
  const driverName = payload.driverName;
  const account = (payload.accounts && payload.accounts[0]) || '';

  if (!driverName) return jsonResponse(res, 400, { error: 'NO_DRIVER_NAME' });

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
  const monthAgo = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();

  let taps = [];
  if (SUPABASE_URL && SUPABASE_KEY) {
    try {
      const tapUrl = `${SUPABASE_URL}/rest/v1/nfc_taps?select=person,tapped_at&person=eq.${encodeURIComponent(driverName)}&order=tapped_at.desc&limit=1000`;
      const r = await fetch(tapUrl, { headers: { 'apikey': SUPABASE_KEY, 'Authorization': 'Bearer ' + SUPABASE_KEY } });
      const j = await r.json();
      if (Array.isArray(j)) taps = j;
    } catch (e) { taps = []; }
  } else {
    // Fallback: read from local tap log
    try {
      const tapLog = require('path').join(__dirname, '.nfc-taps.json');
      const all = JSON.parse(fs.readFileSync(tapLog, 'utf8'));
      taps = all.filter(t => t.person === driverName).map(t => ({ person: t.person, tapped_at: t.ts }));
    } catch (e) { taps = []; }
  }

  // Get all drivers for rank calculation
  const store = loadMetaStore();
  const cards = store['nfc_cards_' + account] || [];
  const cardNames = cards.map(c => c.name || c);

  let allTaps = [];
  if (SUPABASE_URL && SUPABASE_KEY && cardNames.length) {
    try {
      const allUrl = `${SUPABASE_URL}/rest/v1/nfc_taps?select=person,tapped_at&order=tapped_at.desc&limit=5000`;
      const r2 = await fetch(allUrl, { headers: { 'apikey': SUPABASE_KEY, 'Authorization': 'Bearer ' + SUPABASE_KEY } });
      const j2 = await r2.json();
      if (Array.isArray(j2)) allTaps = j2;
    } catch (e) { allTaps = []; }
  } else if (cardNames.length) {
    try {
      const tapLog = require('path').join(__dirname, '.nfc-taps.json');
      const all = JSON.parse(fs.readFileSync(tapLog, 'utf8'));
      allTaps = all.map(t => ({ person: t.person, tapped_at: t.ts }));
    } catch (e) { allTaps = []; }
  }

  const monthCounts = {};
  cardNames.forEach(function(name) {
    monthCounts[name] = allTaps.filter(t => t.person === name && t.tapped_at >= monthAgo).length;
  });
  const sorted = Object.entries(monthCounts).sort((a, b) => b[1] - a[1]);
  const rank = sorted.findIndex(([name]) => name === driverName) + 1;
  const total = sorted.length;

  // 30-day daily breakdown
  const daily = {};
  for (let i = 29; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    daily[key] = taps.filter(t => t.tapped_at && t.tapped_at.startsWith(key)).length;
  }

  // Lookup review link from ACCOUNT_FEATURES or ACCOUNT_PLACE_IDS
  const placeInfo = ACCOUNT_PLACE_IDS[account] || null;
  const reviewLink = placeInfo ? ('https://search.google.com/local/writereview?placeid=' + placeInfo.placeId) : null;

  return jsonResponse(res, 200, {
    driverName,
    account,
    rank: rank || (total + 1),
    totalDrivers: total,
    taps: {
      today: taps.filter(t => t.tapped_at >= todayStart).length,
      week: taps.filter(t => t.tapped_at >= weekAgo).length,
      month: taps.filter(t => t.tapped_at >= monthAgo).length,
      alltime: taps.length
    },
    lastTap: taps[0] ? taps[0].tapped_at : null,
    daily,
    reviewLink
  });
}

async function handleDriverStats(req, res, payload) {
  const qs = Object.fromEntries(new URL('http://x' + req.url).searchParams);
  const account = qs.account || payload.email;
  const period = qs.period || 'month';

  // Get NFC cards for this account
  const cards = metaGet('nfc_cards_' + account) || [];

  // Calculate date cutoffs
  const now = new Date();
  const weekAgo = new Date(now - 7*24*60*60*1000).toISOString();
  const monthAgo = new Date(now - 30*24*60*60*1000).toISOString();
  const todayStart = new Date(new Date().setHours(0,0,0,0)).toISOString();

  // Fallback if no Supabase
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    return jsonResponse(res, 200, { drivers: cards.map(c => ({ name: c.name || c, taps: { today: 0, week: 0, month: 0, alltime: 0 }, lastTap: null, active: false, daily: {} })), period, account });
  }

  // Fetch all taps for these cards from Supabase
  const cardNames = cards.map(c => c.name || c);
  const tapUrl = SUPABASE_URL + '/rest/v1/nfc_taps?select=person,tapped_at&order=tapped_at.desc&limit=5000';
  let taps = [];
  try {
    const tapReq = await fetch(tapUrl, { headers: { 'apikey': SUPABASE_KEY, 'Authorization': 'Bearer ' + SUPABASE_KEY } });
    taps = await tapReq.json();
    if (!Array.isArray(taps)) taps = [];
  } catch(e) { taps = []; }

  // Aggregate per driver
  const drivers = cardNames.map(name => {
    const driverTaps = taps.filter(t => t.person === name);
    const today = driverTaps.filter(t => t.tapped_at >= todayStart).length;
    const week = driverTaps.filter(t => t.tapped_at >= weekAgo).length;
    const month = driverTaps.filter(t => t.tapped_at >= monthAgo).length;
    const alltime = driverTaps.length;
    const lastTap = driverTaps[0] ? driverTaps[0].tapped_at : null;
    const active = lastTap ? (new Date(lastTap) > new Date(Date.now() - 7*24*60*60*1000)) : false;

    // Daily breakdown for last 30 days
    const daily = {};
    for (let i = 29; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0,10);
      daily[key] = driverTaps.filter(t => t.tapped_at && t.tapped_at.startsWith(key)).length;
    }

    return { name, taps: { today, week, month, alltime }, lastTap, active, daily };
  });

  // Sort by selected period desc
  const sortKey = period === 'week' ? 'week' : period === 'alltime' ? 'alltime' : 'month';
  drivers.sort((a, b) => b.taps[sortKey] - a.taps[sortKey]);

  jsonResponse(res, 200, { drivers, period, account });
}

function jsonResponse(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

async function handleConnect(res) {
  const oauth2 = createOAuth2Client();
  if (!oauth2) {
    jsonResponse(res, 200, { error: 'GOOGLE_CREDENTIALS_NOT_CONFIGURED', authUrl: null });
    return;
  }
  const authUrl = oauth2.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/drive.readonly',
      'https://www.googleapis.com/auth/drive.file',
      'https://www.googleapis.com/auth/userinfo.email',
    ],
  });
  jsonResponse(res, 200, { authUrl });
}

async function handleCallback(res, qs) {
  const code = qs.code;
  const error = qs.error;
  const html = (msg, isError) => `<!DOCTYPE html><html><head><title>Google Drive</title></head><body><script>
    window.opener && window.opener.postMessage(${JSON.stringify({ type: 'gdrive-oauth', success: !isError, error: msg || null })}, '*');
    if(!window.opener){ window.location.href = '/#files'; }
    window.close();
  </script><p style="font-family:sans-serif;padding:20px">${isError ? 'Connection failed: ' + msg : 'Connected! You can close this window.'}</p></body></html>`;

  if (error) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html(error, true));
    return;
  }
  if (!code) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html('No authorization code received', true));
    return;
  }
  const oauth2 = createOAuth2Client();
  if (!oauth2) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html('Google credentials not configured', true));
    return;
  }
  try {
    const { tokens } = await oauth2.getToken(code);
    saveTokens(tokens);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html(null, false));
  } catch (e) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html(e.message, true));
  }
}

async function handleStatus(res) {
  const oauth2 = getAuthedClient();
  if (!oauth2) {
    const hasConfig = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
    jsonResponse(res, 200, { connected: false, configured: hasConfig });
    return;
  }
  try {
    const oauth2api = google.oauth2({ version: 'v2', auth: oauth2 });
    const info = await oauth2api.userinfo.get();
    jsonResponse(res, 200, { connected: true, configured: true, user: info.data });
  } catch (e) {
    deleteTokens();
    jsonResponse(res, 200, { connected: false, configured: true, error: e.message });
  }
}

async function handleDisconnect(res) {
  const oauth2 = getAuthedClient();
  if (oauth2) {
    try {
      const tokens = loadTokens();
      const token = tokens && (tokens.access_token || tokens.refresh_token);
      if (token) await oauth2.revokeToken(token);
    } catch (e) {}
  }
  deleteTokens();
  jsonResponse(res, 200, { disconnected: true });
}

async function handleFiles(res, qs) {
  const oauth2 = getAuthedClient();
  if (!oauth2) {
    jsonResponse(res, 200, { files: [], error: 'NOT_CONNECTED' });
    return;
  }
  try {
    const drive = google.drive({ version: 'v3', auth: oauth2 });
    const q = qs.q && qs.q.trim();
    const params = {
      pageSize: 50,
      fields: 'files(id,name,mimeType,size,modifiedTime,webViewLink)',
      orderBy: 'modifiedTime desc',
      q: q ? `name contains '${q.replace(/'/g, "\\'")}' and trashed=false` : 'trashed=false',
    };
    const resp = await drive.files.list(params);
    const files = (resp.data.files || []).map(f => ({
      id: f.id,
      name: f.name,
      mimeType: f.mimeType,
      icon: mimeIcon(f.mimeType),
      size: f.size ? formatBytes(f.size) : null,
      modifiedTime: f.modifiedTime,
      webViewLink: f.webViewLink,
    }));
    jsonResponse(res, 200, { files });
  } catch (e) {
    jsonResponse(res, 200, { files: [], error: e.message });
  }
}

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50MB

function readRequestBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let aborted = false;
    req.on('data', (chunk) => {
      if (aborted) return;
      total += chunk.length;
      if (total > maxBytes) {
        aborted = true;
        reject(new Error('FILE_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => { if (!aborted) resolve(Buffer.concat(chunks)); });
    req.on('error', (e) => { if (!aborted) reject(e); });
  });
}

function parseMultipart(buffer, contentType) {
  const match = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || '');
  if (!match) return null;
  const boundary = '--' + (match[1] || match[2]).trim();
  const boundaryBuf = Buffer.from(boundary);
  const parts = [];
  let start = buffer.indexOf(boundaryBuf);
  if (start === -1) return parts;
  start += boundaryBuf.length;
  while (start < buffer.length) {
    if (buffer[start] === 0x2d && buffer[start + 1] === 0x2d) break;
    if (buffer[start] === 0x0d && buffer[start + 1] === 0x0a) start += 2;
    const next = buffer.indexOf(boundaryBuf, start);
    if (next === -1) break;
    let end = next;
    if (buffer[end - 2] === 0x0d && buffer[end - 1] === 0x0a) end -= 2;
    const partBuf = buffer.slice(start, end);
    const headerEnd = partBuf.indexOf('\r\n\r\n');
    if (headerEnd !== -1) {
      const headerStr = partBuf.slice(0, headerEnd).toString('utf8');
      const body = partBuf.slice(headerEnd + 4);
      const part = { headers: headerStr, body: body, name: null, filename: null, contentType: null };
      const disp = /content-disposition:[^\r\n]*/i.exec(headerStr);
      if (disp) {
        const nameM = /name="([^"]*)"/i.exec(disp[0]);
        const fileM = /filename="([^"]*)"/i.exec(disp[0]);
        if (nameM) part.name = nameM[1];
        if (fileM) part.filename = fileM[1];
      }
      const ctM = /content-type:\s*([^\r\n]+)/i.exec(headerStr);
      if (ctM) part.contentType = ctM[1].trim();
      parts.push(part);
    }
    start = next + boundaryBuf.length;
  }
  return parts;
}

async function handleUpload(req, res) {
  const oauth2 = getAuthedClient();
  if (!oauth2) {
    jsonResponse(res, 200, { error: 'NOT_CONNECTED' });
    return;
  }
  const contentType = req.headers['content-type'] || '';
  if (!contentType.toLowerCase().startsWith('multipart/form-data')) {
    jsonResponse(res, 400, { error: 'EXPECTED_MULTIPART' });
    return;
  }
  let body;
  try {
    body = await readRequestBody(req, MAX_UPLOAD_BYTES);
  } catch (e) {
    if (e && e.message === 'FILE_TOO_LARGE') {
      jsonResponse(res, 413, { error: 'FILE_TOO_LARGE', message: 'File exceeds the 50MB limit.' });
    } else {
      jsonResponse(res, 400, { error: 'UPLOAD_READ_FAILED', message: e.message });
    }
    return;
  }
  const parts = parseMultipart(body, contentType) || [];
  const filePart = parts.find(p => p.filename);
  if (!filePart || !filePart.filename) {
    jsonResponse(res, 400, { error: 'NO_FILE', message: 'No file was provided.' });
    return;
  }
  try {
    const drive = google.drive({ version: 'v3', auth: oauth2 });
    const Readable = require('stream').Readable;
    const mediaStream = Readable.from(filePart.body);
    const resp = await drive.files.create({
      requestBody: { name: filePart.filename },
      media: {
        mimeType: filePart.contentType || 'application/octet-stream',
        body: mediaStream,
      },
      fields: 'id,name,mimeType,size,modifiedTime,webViewLink',
    });
    const f = resp.data;
    jsonResponse(res, 200, {
      success: true,
      file: {
        id: f.id,
        name: f.name,
        mimeType: f.mimeType,
        icon: mimeIcon(f.mimeType),
        size: f.size ? formatBytes(f.size) : null,
        modifiedTime: f.modifiedTime,
        webViewLink: f.webViewLink,
      },
    });
  } catch (e) {
    const msg = e && e.message ? e.message : 'Upload failed';
    const insufficient = /insufficient|permission|scope|403/i.test(msg);
    jsonResponse(res, 200, {
      error: insufficient ? 'INSUFFICIENT_SCOPE' : 'UPLOAD_FAILED',
      message: insufficient
        ? 'Drive write permission is missing. Please disconnect and reconnect Google Drive to grant upload access.'
        : msg,
    });
  }
}

// ============ GOOGLE OAUTH (GBP / GSC / CALENDAR) ============
function getGoogleRedirectUri() {
  const domain = process.env.REPLIT_DEV_DOMAIN || process.env.REPLIT_DOMAINS || `localhost:${PORT}`;
  const host = domain.split(',')[0].trim();
  return `https://${host}/api/google/callback`;
}

function createGoogleOAuth2Client() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return new google.auth.OAuth2(clientId, clientSecret, getGoogleRedirectUri());
}

function loadGoogleTokens() {
  try { if (fs.existsSync(GOOGLE_TOKEN_FILE)) return JSON.parse(fs.readFileSync(GOOGLE_TOKEN_FILE, 'utf8')); } catch (e) {}
  return null;
}
function saveGoogleTokens(tokens) { fs.writeFileSync(GOOGLE_TOKEN_FILE, JSON.stringify(tokens, null, 2)); }
function deleteGoogleTokens() { try { if (fs.existsSync(GOOGLE_TOKEN_FILE)) fs.unlinkSync(GOOGLE_TOKEN_FILE); } catch (e) {} }

function getGoogleAuthedClient() {
  const oauth2 = createGoogleOAuth2Client();
  if (!oauth2) return null;
  const tokens = loadGoogleTokens();
  if (!tokens) return null;
  oauth2.setCredentials(tokens);
  oauth2.on('tokens', (t) => { const cur = loadGoogleTokens() || {}; saveGoogleTokens(Object.assign({}, cur, t)); });
  return oauth2;
}

async function handleGoogleConnect(res) {
  const oauth2 = createGoogleOAuth2Client();
  if (!oauth2) { jsonResponse(res, 200, { error: 'GOOGLE_CREDENTIALS_NOT_CONFIGURED', authUrl: null }); return; }
  const authUrl = oauth2.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/business.manage',
      'https://www.googleapis.com/auth/webmasters.readonly',
      'https://www.googleapis.com/auth/calendar.readonly',
    ],
  });
  jsonResponse(res, 200, { authUrl });
}

async function handleGoogleCallback(res, qs) {
  const html = (msg, isError) => `<!DOCTYPE html><html><head><title>Google</title></head><body><script>
    window.opener && window.opener.postMessage(${JSON.stringify({ type: 'google-oauth', success: !isError, error: msg || null })}, '*');
    if(!window.opener){ window.location.href = '/#settings'; }
    window.close();
  </script><p style="font-family:sans-serif;padding:20px">${isError ? 'Connection failed: ' + msg : 'Connected! You can close this window.'}</p></body></html>`;

  if (qs.error) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html(qs.error, true)); return; }
  if (!qs.code) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html('No code received', true)); return; }
  const oauth2 = createGoogleOAuth2Client();
  if (!oauth2) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html('Google credentials not configured', true)); return; }
  try {
    const { tokens } = await oauth2.getToken(qs.code);
    saveGoogleTokens(tokens);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html(null, false));
  } catch (e) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html(e.message, true)); }
}

async function handleGoogleStatus(res) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) {
    jsonResponse(res, 200, { connected: false, configured: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) });
    return;
  }
  try {
    const api = google.oauth2({ version: 'v2', auth: oauth2 });
    const info = await api.userinfo.get();
    jsonResponse(res, 200, { connected: true, configured: true, user: info.data });
  } catch (e) { deleteGoogleTokens(); jsonResponse(res, 200, { connected: false, configured: true, error: e.message }); }
}

async function handleGoogleDisconnect(res) {
  const oauth2 = getGoogleAuthedClient();
  if (oauth2) { try { const t = loadGoogleTokens(); const tok = t && (t.access_token || t.refresh_token); if (tok) await oauth2.revokeToken(tok); } catch (e) {} }
  deleteGoogleTokens();
  jsonResponse(res, 200, { disconnected: true });
}

// Helper: authenticated HTTPS request using OAuth2 access token
async function googleApiGet(oauth2, url) {
  const tokenInfo = await oauth2.getAccessToken();
  const accessToken = tokenInfo.token || tokenInfo.res?.data?.access_token;
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const opts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      headers: { 'Authorization': 'Bearer ' + accessToken, 'Accept': 'application/json' },
    };
    require('https').get(opts, r => {
      let d = ''; r.on('data', c => d += c);
      r.on('end', () => { try { resolve({ status: r.statusCode, body: JSON.parse(d) }); } catch(e) { resolve({ status: r.statusCode, body: {} }); } });
    }).on('error', reject);
  });
}

// ---- GBP ----
async function handleGBPAccounts(res) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', accounts: [] }); return; }
  try {
    const r = await googleApiGet(oauth2, 'https://mybusinessaccountmanagement.googleapis.com/v1/accounts');
    jsonResponse(res, 200, { accounts: r.body.accounts || [] });
  } catch (e) { jsonResponse(res, 200, { error: e.message, accounts: [] }); }
}

async function handleGBPLocations(res, qs) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', locations: [] }); return; }
  const account = qs.account;
  if (!account) { jsonResponse(res, 400, { error: 'MISSING_ACCOUNT' }); return; }
  try {
    const r = await googleApiGet(oauth2, `https://mybusinessbusinessinformation.googleapis.com/v1/${account}/locations?readMask=name,title,storefrontAddress,websiteUri`);
    jsonResponse(res, 200, { locations: r.body.locations || [] });
  } catch (e) { jsonResponse(res, 200, { error: e.message, locations: [] }); }
}

async function handleGBPReviews(res, qs) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', reviews: [] }); return; }
  const location = qs.location;
  if (!location) { jsonResponse(res, 400, { error: 'MISSING_LOCATION' }); return; }
  try {
    const r = await googleApiGet(oauth2, `https://mybusiness.googleapis.com/v4/${location}/reviews`);
    jsonResponse(res, 200, { reviews: r.body.reviews || [], averageRating: r.body.averageRating || null });
  } catch (e) { jsonResponse(res, 200, { error: e.message, reviews: [] }); }
}

async function handleGBPReply(req, res) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED' }); return; }
  let body;
  try { const raw = await readRequestBody(req, 32 * 1024); body = JSON.parse(raw.toString('utf8')); } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  const { location, reviewId, comment } = body || {};
  if (!location || !reviewId || !comment) { jsonResponse(res, 400, { error: 'MISSING_FIELDS' }); return; }
  try {
    const tokenInfo = await oauth2.getAccessToken();
    const accessToken = tokenInfo.token;
    const data = JSON.stringify({ comment });
    await new Promise((resolve, reject) => {
      const opts = {
        hostname: 'mybusiness.googleapis.com',
        path: `/v4/${location}/reviews/${reviewId}/reply`,
        method: 'PUT',
        headers: { 'Authorization': 'Bearer ' + accessToken, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      };
      const r = require('https').request(opts, res2 => { let d = ''; res2.on('data', c => d += c); res2.on('end', () => resolve({ status: res2.statusCode })); });
      r.on('error', reject); r.write(data); r.end();
    });
    jsonResponse(res, 200, { ok: true });
  } catch (e) { jsonResponse(res, 200, { error: e.message }); }
}

// ---- GSC ----
async function handleGSCSites(res) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', sites: [] }); return; }
  try {
    const sc = google.searchconsole({ version: 'v1', auth: oauth2 });
    const r = await sc.sites.list();
    jsonResponse(res, 200, { sites: r.data.siteEntry || [] });
  } catch (e) { jsonResponse(res, 200, { error: e.message, sites: [] }); }
}

async function handleGSCAnalytics(req, res, qs) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', rows: [] }); return; }
  const siteUrl = qs.siteUrl;
  if (!siteUrl) { jsonResponse(res, 400, { error: 'MISSING_SITE_URL' }); return; }
  let body = {};
  if (req.method === 'POST') {
    try { const raw = await readRequestBody(req, 32 * 1024); body = JSON.parse(raw.toString('utf8')); } catch (e) {}
  }
  const requestBody = Object.assign({
    startDate: body.startDate || new Date(Date.now() - 28 * 86400000).toISOString().slice(0, 10),
    endDate: body.endDate || new Date().toISOString().slice(0, 10),
    dimensions: body.dimensions || ['query'],
    rowLimit: body.rowLimit || 25,
  }, body);
  try {
    const sc = google.searchconsole({ version: 'v1', auth: oauth2 });
    const r = await sc.searchanalytics.query({ siteUrl, requestBody });
    jsonResponse(res, 200, { rows: r.data.rows || [], responseAggregationType: r.data.responseAggregationType });
  } catch (e) { jsonResponse(res, 200, { error: e.message, rows: [] }); }
}

// ---- Calendar ----
async function handleCalendarEvents(res, qs) {
  const oauth2 = getGoogleAuthedClient();
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', events: [] }); return; }
  try {
    const cal = google.calendar({ version: 'v3', auth: oauth2 });
    const now = new Date();
    const params = {
      calendarId: qs.calendarId || 'primary',
      timeMin: qs.timeMin || now.toISOString(),
      timeMax: qs.timeMax || new Date(now.getTime() + 30 * 86400000).toISOString(),
      singleEvents: true,
      orderBy: 'startTime',
      maxResults: parseInt(qs.maxResults) || 50,
    };
    const r = await cal.events.list(params);
    const events = (r.data.items || []).map(e => ({
      id: e.id,
      summary: e.summary,
      description: e.description,
      start: e.start,
      end: e.end,
      location: e.location,
      htmlLink: e.htmlLink,
      attendees: e.attendees,
      status: e.status,
    }));
    jsonResponse(res, 200, { events });
  } catch (e) { jsonResponse(res, 200, { error: e.message, events: [] }); }
}

// ============ STRIPE ============
async function stripeApiRequest(method, path, body) {
  const key = (process.env.STRIPE_SECRET_KEY || '').replace(/[^\x20-\x7E]/g, '').trim();
  if (!key) throw new Error('STRIPE_SECRET_KEY not set');
  return new Promise((resolve, reject) => {
    const data = body ? new URLSearchParams(body).toString() : null;
    const opts = {
      hostname: 'api.stripe.com',
      path,
      method,
      headers: {
        'Authorization': 'Basic ' + Buffer.from(key + ':').toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
        'Stripe-Version': '2023-10-16',
      },
    };
    if (data) opts.headers['Content-Length'] = Buffer.byteLength(data);
    const r = require('https').request(opts, res2 => {
      let d = ''; res2.on('data', c => d += c);
      res2.on('end', () => { try { resolve({ status: res2.statusCode, body: JSON.parse(d) }); } catch(e) { resolve({ status: res2.statusCode, body: {} }); } });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

const STRIPE_TOKEN_FILE = path.join(__dirname, '.stripe-connect.json');
function loadStripeConnect() { try { if (fs.existsSync(STRIPE_TOKEN_FILE)) return JSON.parse(fs.readFileSync(STRIPE_TOKEN_FILE, 'utf8')); } catch (e) {} return null; }
function saveStripeConnect(data) { fs.writeFileSync(STRIPE_TOKEN_FILE, JSON.stringify(data, null, 2)); }
function deleteStripeConnect() { try { if (fs.existsSync(STRIPE_TOKEN_FILE)) fs.unlinkSync(STRIPE_TOKEN_FILE); } catch (e) {} }

// Auto-seed Stripe config on startup if key is set but file is missing
if (process.env.STRIPE_SECRET_KEY && !fs.existsSync(STRIPE_TOKEN_FILE)) {
  stripeApiRequest('GET', '/v1/account', null).then(function(r) {
    if (r.status === 200 && r.body && r.body.id) {
      saveStripeConnect({ accountId: r.body.id, email: r.body.email, country: r.body.country, connectedAt: Date.now() });
      console.log('[Stripe] Auto-seeded config for account', r.body.id);
    } else {
      console.warn('[Stripe] Auto-seed: unexpected response status', r.status);
    }
  }).catch(function(e) {
    console.error('[Stripe] Auto-seed failed:', e.message);
  });
}

async function handleStripeConnect(req, res) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) { jsonResponse(res, 200, { ok: false, error: 'STRIPE_SECRET_KEY not set' }); return; }
  try {
    const r = await stripeApiRequest('GET', '/v1/account', null);
    if (r.status === 200 && r.body.id) {
      saveStripeConnect({ accountId: r.body.id, email: r.body.email, country: r.body.country, connectedAt: Date.now() });
      jsonResponse(res, 200, { ok: true, accountId: r.body.id, email: r.body.email });
    } else {
      jsonResponse(res, 200, { ok: false, error: r.body.error?.message || 'Stripe connection failed' });
    }
  } catch (e) { jsonResponse(res, 200, { ok: false, error: e.message }); }
}

async function handleStripeStatus(res) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) { jsonResponse(res, 200, { connected: false, configured: false }); return; }
  try {
    const r = await stripeApiRequest('GET', '/v1/account', null);
    if (r.status === 200 && r.body.id) {
      const saved = loadStripeConnect();
      if (!saved) saveStripeConnect({ accountId: r.body.id, email: r.body.email, country: r.body.country, connectedAt: Date.now() });
      jsonResponse(res, 200, { connected: true, configured: true, accountId: r.body.id, email: r.body.email, country: r.body.country });
    } else {
      jsonResponse(res, 200, { connected: false, configured: true, error: r.body.error?.message });
    }
  } catch (e) { jsonResponse(res, 200, { connected: false, configured: true, error: e.message }); }
}

async function handleStripeRevenue(res, qs) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', charges: [], total: 0 }); return; }
  try {
    const limit = Math.min(parseInt(qs.limit) || 20, 100);
    const params = new URLSearchParams({ limit: limit.toString() });
    if (qs.created_gte) params.set('created[gte]', qs.created_gte);
    if (qs.created_lte) params.set('created[lte]', qs.created_lte);
    const r = await stripeApiRequest('GET', '/v1/charges?' + params.toString(), null);
    const charges = (r.body.data || []).map(c => ({
      id: c.id,
      amount: c.amount,
      currency: c.currency,
      status: c.status,
      description: c.description,
      customer: c.customer,
      created: c.created,
      receipt_url: c.receipt_url,
    }));
    const total = charges.filter(c => c.status === 'succeeded').reduce((s, c) => s + c.amount, 0);
    jsonResponse(res, 200, { charges, total, currency: charges[0]?.currency || 'usd' });
  } catch (e) { jsonResponse(res, 200, { error: e.message, charges: [], total: 0 }); }
}

async function handleStripeDisconnect(res) {
  deleteStripeConnect();
  jsonResponse(res, 200, { disconnected: true });
}

// ============ GOOGLE PLACES REVIEWS (no OAuth) ============
async function handlePlacesReviews(res, qs) {
  const account = qs.account || '';
  const accountData = ACCOUNT_PLACE_IDS[account];
  if (!accountData) { jsonResponse(res, 400, { error: 'Unknown account' }); return; }
  const placeId = accountData.placeId;
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;
  if (!apiKey) { jsonResponse(res, 200, { error: 'GOOGLE_MAPS_API_KEY not set', reviews: [] }); return; }
  try {
    const r = await new Promise((resolve, reject) => {
      const url = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}&fields=name,rating,user_ratings_total,reviews&key=${apiKey}`;
      const parsed = new (require('url').URL)(url);
      require('https').get({ hostname: parsed.hostname, path: parsed.pathname + parsed.search }, res2 => {
        let d = ''; res2.on('data', c => d += c);
        res2.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve({}); } });
      }).on('error', reject);
    });
    const result = r.result || {};
    const reviews = (result.reviews || []).map(rev => ({
      author_name: rev.author_name,
      rating: rev.rating,
      text: rev.text,
      time: rev.time,
      relative_time_description: rev.relative_time_description,
      profile_photo_url: rev.profile_photo_url,
    }));
    const lowStarAlerts = reviews.filter(r => r.rating <= 2);
    const out = {
      name: result.name || accountData.name,
      rating: result.rating || null,
      total: result.user_ratings_total || 0,
      reviews,
      lowStarAlerts,
    };
    // Cache reviews for home/stats aggregation
    try {
      const store = loadMetaStore();
      store['reviews_cache_' + account] = reviews.map(r => ({ ...r, date: r.time ? new Date(r.time * 1000).toISOString() : null }));
      store['reviews_cache_meta_' + account] = { rating: out.rating, total: out.total, name: out.name, cachedAt: new Date().toISOString() };
      saveMetaStoreQueued(store);
    } catch(e) {}
    jsonResponse(res, 200, out);
  } catch(e) { jsonResponse(res, 200, { error: e.message, reviews: [] }); }
}

// ============ NFC CARD REGISTRY ============
async function handleNfcCardsGet(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const account = qs.account || payload.email;
  const store = loadMetaStore();
  const cards = store[`nfc_cards_${account}`] || [];
  jsonResponse(res, 200, { cards });
}

function getNfcCardStats(person, accountId) {
  try {
    const tapLog = path.join(__dirname, '.nfc-taps.json');
    let taps = [];
    try { taps = JSON.parse(fs.readFileSync(tapLog, 'utf8')); } catch(e) {}
    const cardTaps = taps.filter(t => t.person === person && t.accountId === accountId);
    const total = cardTaps.length;
    const clicks = cardTaps.filter(t => t.reviewClick).length;
    const now = new Date();
    const todayStr = now.toISOString().slice(0,10);
    const weekAgo = new Date(now - 7*24*60*60*1000).toISOString();
    const monthAgo = new Date(now - 30*24*60*60*1000).toISOString();
    const today = cardTaps.filter(t => t.ts && t.ts.startsWith(todayStr)).length;
    const week = cardTaps.filter(t => t.ts && t.ts >= weekAgo).length;
    const month = cardTaps.filter(t => t.ts && t.ts >= monthAgo).length;
    const lastTap = cardTaps.length ? cardTaps[cardTaps.length-1].ts : null;
    return { total, today, week, month, clicks, conversion: total ? Math.round(clicks/total*100) : 0, lastTap };
  } catch(e) { return { total:0, today:0, week:0, clicks:0, conversion:0, lastTap:null }; }
}

function handleNfcTapsGet(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const account = qs.account || payload.email;
  try {
    const tapLog = path.join(__dirname, '.nfc-taps.json');
    let taps = [];
    try { taps = JSON.parse(fs.readFileSync(tapLog, 'utf8')); } catch(e) {}
    // Filter by accountId field (new) with fallback to card-name matching (legacy)
    const store = loadMetaStore();
    const cards = store[`nfc_cards_${account}`] || [];
    const cardNames = new Set(cards.map(c => c.name.toLowerCase()));
    const filtered = taps.filter(t => t.accountId === account || cardNames.has((t.person||'').toLowerCase()));
    // Return enriched records
    const result = filtered.map(t => ({ person: t.person, tapped_at: t.ts, ip: t.ip||'', reviewClick: !!t.reviewClick }));
    // Also compute per-card stats
    const stats = {};
    cards.forEach(c => { stats[c.name] = getNfcCardStats(c.name, account); });
    jsonResponse(res, 200, { taps: result, stats });
  } catch(e) {
    jsonResponse(res, 500, { error: e.message, taps: [], stats:{}});
  }
}

function _handleNfcTapsGet_REPLACED(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const account = qs.account || payload.email;
  try {
    const tapLog = path.join(__dirname, '.nfc-taps.json');
    let taps = [];
    try { taps = JSON.parse(fs.readFileSync(tapLog, 'utf8')); } catch(e) {}
    // Filter taps to those belonging to cards registered under this account
    const store = loadMetaStore();
    const cards = store[`nfc_cards_${account}`] || [];
    const cardNames = new Set(cards.map(c => c.name.toLowerCase()));
    const filtered = taps.filter(t => cardNames.has((t.person || '').toLowerCase()));
    // Return with tapped_at field name matching what the client expects
    const result = filtered.map(t => ({ person: t.person, tapped_at: t.ts, ip: t.ip || '' }));
    jsonResponse(res, 200, { taps: result });
  } catch(e) {
    jsonResponse(res, 500, { error: e.message, taps: [] });
  }
}

async function handleNfcCardsPost(req, res) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  let body;
  try { const raw = await readRequestBody(req, 32*1024); body = JSON.parse(raw.toString('utf8')); } catch(e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  const { name, account, placeId, cid } = body || {};
  if (!name) { jsonResponse(res, 400, { error: 'MISSING_NAME' }); return; }
  const acct = account || payload.email;
  const store = loadMetaStore();
  const key = `nfc_cards_${acct}`;
  const cards = store[key] || [];
  if (cards.find(c => c.name.toLowerCase() === name.toLowerCase())) {
    jsonResponse(res, 409, { error: 'Card with this name already exists' }); return;
  }
  cards.push({ name, placeId: placeId || null, cid: cid || null, createdAt: new Date().toISOString() });
  store[key] = cards;
  saveMetaStoreQueued(store);
  jsonResponse(res, 200, { ok: true, card: cards[cards.length - 1], tapUrl: `/tap/${encodeURIComponent(name)}` });
}

async function handleNfcCardsDelete(req, res) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const raw = await readRequestBody(req, 8*1024);
  let body = {};
  try { body = JSON.parse(raw); } catch(e) {}
  const account = body.account || payload.email;
  const name = (body.name || '').trim();
  if (!name) { jsonResponse(res, 400, { error: 'name required' }); return; }
  const store = loadMetaStore();
  const cards = (store[`nfc_cards_${account}`] || []).filter(c => c.name !== name);
  store[`nfc_cards_${account}`] = cards;
  saveMetaStoreQueued(store);
  jsonResponse(res, 200, { ok: true, remaining: cards.length });
}

async function handleNfcStats(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const accountId = qs.accountId || qs.account || payload.email;
  const cardId = qs.cardId || '';
  if (!cardId) { jsonResponse(res, 400, { error: 'cardId required' }); return; }
  const stats = getNfcCardStats(cardId, accountId);
  jsonResponse(res, 200, stats);
}

async function handleDriversStats(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const account = qs.account || payload.email;
  const period = qs.period || 'month';
  const store = loadMetaStore();
  const cards = store[`nfc_cards_${account}`] || [];
  const drivers = cards.map(card => {
    const stats = getNfcCardStats(card.name, account);
    return {
      name: card.name,
      reviewUrl: card.reviewUrl || null,
      lastTap: stats.lastTap || null,
      taps: {
        today: stats.today || 0,
        week: stats.week || 0,
        month: stats.month || 0,
        alltime: stats.total || 0
      }
    };
  });
  // Sort by selected period
  const key = period === 'week' ? 'week' : period === 'alltime' ? 'alltime' : 'month';
  drivers.sort((a, b) => (b.taps[key] || 0) - (a.taps[key] || 0));
  jsonResponse(res, 200, { drivers, period });
}


// ============ NFC TAP LANDING PAGE ============
function logNfcTap(person, accountId, req) {
  try {
    const tapLog = path.join(__dirname, '.nfc-taps.json');
    let taps = [];
    try { taps = JSON.parse(fs.readFileSync(tapLog, 'utf8')); } catch(e) {}
    taps.push({ person, accountId: accountId || 'unknown', ts: new Date().toISOString(), ip: req.socket?.remoteAddress || '', reviewClick: false });
    if (taps.length > 5000) taps = taps.slice(-5000);
    fs.writeFileSync(tapLog, JSON.stringify(taps));
  } catch(e) {}
}

function buildDriverPage(person, reviewUrl) {
  const safeUrl = reviewUrl || '#';
  const initials = person.split(' ').map(w => w[0]||'').join('').toUpperCase().slice(0,2) || '??';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${htmlEscape(person)} — Leave a Review</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e1a3a 100%); color: #f1f5f9; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; text-align: center; }
  .card { background: rgba(255,255,255,0.05); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 40px 28px; max-width: 380px; width: 100%; }
  .avatar { width: 90px; height: 90px; border-radius: 50%; background: linear-gradient(135deg, #f59e0b, #d97706); display: flex; align-items: center; justify-content: center; font-size: 30px; font-weight: 800; color: white; margin: 0 auto 20px; letter-spacing: 1px; box-shadow: 0 0 0 4px rgba(245,158,11,0.2); }
  .badge { display: inline-block; background: rgba(245,158,11,0.15); color: #f59e0b; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; padding: 4px 12px; border-radius: 99px; margin-bottom: 14px; }
  h1 { font-size: 24px; font-weight: 800; margin-bottom: 8px; }
  .tagline { color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 28px; }
  .stars { font-size: 26px; margin-bottom: 20px; letter-spacing: 2px; }
  .btn { display: flex; align-items: center; justify-content: center; gap: 10px; background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; text-decoration: none; padding: 16px 24px; border-radius: 14px; font-size: 16px; font-weight: 700; box-shadow: 0 8px 20px rgba(37,99,235,0.35); transition: transform .15s; }
  .btn:active { transform: scale(0.97); }
  .footer { margin-top: 24px; font-size: 11px; color: #475569; }
</style>
</head>
<body>
  <div class="card">
    <div class="avatar">${initials}</div>
    <div class="badge">Your Service Provider</div>
    <h1>${htmlEscape(person)}</h1>
    <div class="stars">⭐⭐⭐⭐⭐</div>
    <p class="tagline">Happy with the service today?<br>A quick review helps our team grow — it only takes 30 seconds!</p>
    <a class="btn" href="${safeUrl}" id="review-btn">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9V8h2v8zm4 0h-2V8h2v8z" fill="white" opacity="0"/><circle cx="12" cy="12" r="10" stroke="white" stroke-width="1.5" fill="none"/><path d="M9 9l6 3-6 3V9z" fill="white"/></svg>
      Leave a Google Review
    </a>
    <p class="footer">Powered by CAL Marketing</p>
  </div>
  <script>
    const params = new URLSearchParams(location.search);
    const cid = params.get('cid');
    const placeid = params.get('placeid');
    const btn = document.getElementById('review-btn');
    if (btn.getAttribute('href') === '#') {
      if (placeid) btn.href = 'https://search.google.com/local/writereview?placeid=' + placeid;
      else if (cid) btn.href = 'https://www.google.com/maps?cid=' + cid;
    }
    btn.addEventListener('click', function() {
      fetch('/api/nfc/click', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ person: ${JSON.stringify(person)}, ts: new Date().toISOString() }) }).catch(() => {});
    });
    // Auto-redirect after 2s if we have a real review URL
    if (btn.getAttribute('href') && btn.getAttribute('href') !== '#') {
      var bar = document.createElement('div');
      bar.style.cssText = 'position:fixed;bottom:0;left:0;height:4px;background:linear-gradient(90deg,#f59e0b,#2563eb);animation:prog 2s linear forwards;';
      var style = document.createElement('style');
      style.textContent = '@keyframes prog{from{width:0}to{width:100%}}';
      document.head.appendChild(style);
      document.body.appendChild(bar);
      setTimeout(function() {
        fetch('/api/nfc/click', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ person: ${JSON.stringify(person)}, ts: new Date().toISOString() }) }).catch(() => {});
        window.location.href = btn.getAttribute('href');
      }, 2000);
    }
  </script>
</body>
</html>`;
}

function buildTapPage(person, reviewUrl, stats) {
  const safeUrl = reviewUrl || '#';
  const initials = person.split(' ').map(w => w[0]||'').join('').toUpperCase().slice(0,2) || '??';
  const totalTaps = (stats && stats.total) || 0;
  const todayTaps = (stats && stats.today) || 0;
  const weekTaps  = (stats && stats.week)  || 0;
  const conversion = (stats && stats.conversion) || 0;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${htmlEscape(person)} — Leave a Review</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:linear-gradient(135deg,#0f172a 0%,#1e1a3a 100%); color:#f1f5f9; display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:100vh; padding:24px; text-align:center; }
  .card { background:rgba(255,255,255,0.05); backdrop-filter:blur(20px); border:1px solid rgba(255,255,255,0.1); border-radius:24px; padding:40px 28px; max-width:380px; width:100%; }
  .avatar { width:90px; height:90px; border-radius:50%; background:linear-gradient(135deg,#f59e0b,#d97706); display:flex; align-items:center; justify-content:center; font-size:30px; font-weight:800; color:white; margin:0 auto 20px; letter-spacing:1px; box-shadow:0 0 0 4px rgba(245,158,11,0.2); }
  .badge { display:inline-block; background:rgba(245,158,11,0.15); color:#f59e0b; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; padding:4px 12px; border-radius:99px; margin-bottom:14px; }
  h1 { font-size:24px; font-weight:800; margin-bottom:8px; }
  .tagline { color:#94a3b8; font-size:14px; line-height:1.6; margin-bottom:28px; }
  .stars { font-size:26px; margin-bottom:20px; letter-spacing:2px; }
  .btn { display:flex; align-items:center; justify-content:center; gap:10px; background:linear-gradient(135deg,#2563eb,#1d4ed8); color:white; text-decoration:none; padding:16px 24px; border-radius:14px; font-size:16px; font-weight:700; box-shadow:0 8px 20px rgba(37,99,235,0.35); transition:transform .15s; margin-bottom:20px; }
  .btn:active { transform:scale(0.97); }
  .stats-row { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-top:8px; }
  .stat { background:rgba(255,255,255,0.06); border-radius:12px; padding:12px 6px; }
  .stat-val { font-size:20px; font-weight:800; color:#f59e0b; }
  .stat-lbl { font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.05em; margin-top:2px; }
  .footer { margin-top:20px; font-size:11px; color:#475569; }
</style>
</head>
<body>
  <div class="card">
    <div class="avatar">${initials}</div>
    <div class="badge">Your Service Provider</div>
    <h1>${htmlEscape(person)}</h1>
    <div class="stars">⭐⭐⭐⭐⭐</div>
    <p class="tagline">Happy with the service today?<br>A quick review helps our team grow — it only takes 30 seconds!</p>
    <a class="btn" href="${safeUrl}" id="review-btn">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="white" stroke-width="1.5" fill="none"/><path d="M9 9l6 3-6 3V9z" fill="white"/></svg>
      Leave a Review
    </a>
    <div class="stats-row">
      <div class="stat"><div class="stat-val">${totalTaps}</div><div class="stat-lbl">Total Taps</div></div>
      <div class="stat"><div class="stat-val">${todayTaps}</div><div class="stat-lbl">Today</div></div>
      <div class="stat"><div class="stat-val">${conversion}%</div><div class="stat-lbl">Conversion</div></div>
    </div>
    <p class="footer">Powered by CAL Marketing</p>
  </div>
  <script>
    const params = new URLSearchParams(location.search);
    const cid = params.get('cid');
    const placeid = params.get('placeid');
    const btn = document.getElementById('review-btn');
    if (btn.getAttribute('href') === '#') {
      if (placeid) btn.href = 'https://search.google.com/local/writereview?placeid=' + placeid;
      else if (cid) btn.href = 'https://www.google.com/maps?cid=' + cid;
    }
    btn.addEventListener('click', function() {
      fetch('/api/nfc/click', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ person: ${JSON.stringify(person)}, ts: new Date().toISOString() }) }).catch(()=>{});
    });
    // Auto-refresh stats every 30 seconds
    setInterval(function(){
      fetch('/api/nfc/stats?cardId=' + encodeURIComponent(${JSON.stringify(person)}))
        .then(r=>r.json()).then(function(d){
          if(!d || d.error) return;
          document.querySelector('.stats-row').innerHTML =
            '<div class="stat"><div class="stat-val">'+(d.total||0)+'</div><div class="stat-lbl">Total Taps</div></div>' +
            '<div class="stat"><div class="stat-val">'+(d.today||0)+'</div><div class="stat-lbl">Today</div></div>' +
            '<div class="stat"><div class="stat-val">'+(d.conversion||0)+'%</div><div class="stat-lbl">Conversion</div></div>';
        }).catch(()=>{});
    }, 30000);
  </script>
</body>
</html>`;
}


// ── In-App Messaging ──
async function handleMessageGet(req, res, payload) {
  const qs = Object.fromEntries(new URL('http://x' + req.url).searchParams);
  const account = qs.account || payload.email;
  if (!account) { jsonResponse(res, 400, { error: 'MISSING_ACCOUNT' }); return; }
  const store = loadMetaStore();
  const key = 'messages_' + account;
  let msgs = store[key] || [];
  // Mark client messages as read when fetched by admin or different user
  if (payload.role === 'admin' || payload.email !== account) {
    msgs = msgs.map(m => m.senderRole === 'client' ? Object.assign({}, m, { read: true }) : m);
    store[key] = msgs;
    saveMetaStoreQueued(store);
  }
  const unread = msgs.filter(m => !m.read && m.senderRole === 'client').length;
  jsonResponse(res, 200, { messages: msgs, unread });
}

async function handleMessagePost(req, res, payload) {
  let body;
  try { const raw = await readRequestBody(req, 8 * 1024); body = JSON.parse(raw.toString('utf8')); } catch(e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  const { account, text, senderName, senderRole } = body;
  if (!account || !text) { jsonResponse(res, 400, { error: 'MISSING_FIELDS' }); return; }
  const store = loadMetaStore();
  const key = 'messages_' + account;
  const msgs = store[key] || [];
  const msg = {
    id: Date.now() + '_' + Math.random().toString(36).slice(2, 7),
    account,
    text: String(text).slice(0, 1000),
    senderName: senderName || 'Client',
    senderRole: senderRole || 'client',
    timestamp: new Date().toISOString(),
    read: false
  };
  msgs.push(msg);
  if (msgs.length > 200) msgs.splice(0, msgs.length - 200);
  store[key] = msgs;
  saveMetaStoreQueued(store);
  jsonResponse(res, 200, { ok: true, message: msg });
}

async function handleMessageRead(req, res, payload) {
  let body;
  try { const raw = await readRequestBody(req, 4 * 1024); body = JSON.parse(raw.toString('utf8')); } catch(e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  const { account } = body;
  if (!account) { jsonResponse(res, 400, { error: 'MISSING_ACCOUNT' }); return; }
  const store = loadMetaStore();
  const key = 'messages_' + account;
  store[key] = (store[key] || []).map(m => Object.assign({}, m, { read: true }));
  saveMetaStoreQueued(store);
  jsonResponse(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];
  const qs = parseQueryString(req.url);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (urlPath === '/api/config' && req.method === 'GET') {
    // SECURITY NOTE (C-5): The Maps API key returned here should be restricted to this app's
    // domain in Google Cloud Console -> APIs & Services -> Credentials to prevent key abuse.
    jsonResponse(res, 200, { mapsKey: process.env.GOOGLE_MAPS_API_KEY || '' });
    return;
  }

  if (urlPath === '/api/drive/connect' && req.method === 'GET') {
    await handleConnect(res);
    return;
  }
  if (urlPath === '/api/drive/callback' && req.method === 'GET') {
    await handleCallback(res, qs);
    return;
  }
  if (urlPath === '/api/drive/status' && req.method === 'GET') {
    await handleStatus(res);
    return;
  }
  if (urlPath === '/api/drive/disconnect' && req.method === 'POST') {
    await handleDisconnect(res);
    return;
  }
  if (urlPath === '/api/drive/files' && req.method === 'GET') {
    await handleFiles(res, qs);
    return;
  }
  if (urlPath === '/api/drive/upload' && req.method === 'POST') {
    await handleUpload(req, res);
    return;
  }

  // ── Agency PIN login ──
  if (urlPath === '/api/agency-pin' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    await new Promise(r => req.on('end', r));
    let pin = '';
    try { pin = JSON.parse(body).pin || ''; } catch(e) {}
    const AGENCY_PIN = process.env.AGENCY_PIN || '1234';
    if (pin !== AGENCY_PIN) {
      jsonResponse(res, 401, { ok: false, error: 'Invalid PIN' });
      return;
    }
    const serverAccounts = ['apexlegal', 'greencollаr', 'willydiamond', 'housesautobody', 'info@unitedsewerservice.com'];
    const payload = { email: 'admin@cal.marketing', role: 'superadmin', calRole: 'superadmin', accounts: serverAccounts, displayName: 'Agency Admin', exp: Date.now() + TOKEN_TTL_MS };
    const sessionToken = signMetaToken(payload);
    jsonResponse(res, 200, { ok: true, token: sessionToken, role: 'superadmin', displayName: 'Agency Admin', email: 'admin@cal.marketing' });
    return;
  }

  // ── Agency login — direct superadmin session (Replit-hosted, owner only) ──
  if (urlPath === '/api/login' && req.method === 'GET') {
    const serverAccounts = ['apexlegal', 'greencollаr', 'willydiamond', 'housesautobody', 'info@unitedsewerservice.com'];
    const payload = { email: 'admin@cal.marketing', role: 'superadmin', calRole: 'superadmin', accounts: serverAccounts, displayName: 'Agency Admin', exp: Date.now() + TOKEN_TTL_MS };
    const sessionToken = signMetaToken(payload);
    const html = `<!DOCTYPE html><html><head><title>Signing in...</title></head><body style="background:#0a0a0a">
<script>
try{localStorage.setItem('cal-meta-session-token',${JSON.stringify(sessionToken)});}catch(e){}
try{localStorage.setItem('cal-user-role','superadmin');}catch(e){}
try{localStorage.setItem('cal-display-name','Agency Admin');}catch(e){}
try{localStorage.setItem('cal-user-email','admin@cal.marketing');}catch(e){}
window.location.replace('/');
</script></body></html>`;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
    return;
  }


  // ── CAL-native auth login (email + password → token with role) ──
  // ── /api/auth/user — CAL auth check (intercepted before Replit) ──
  // Frontend calls this on every page load. We own this endpoint.
  // If request has a valid CAL token → return the user identity from it.
  // If no token or expired → return 401 so frontend shows login screen.
  if (urlPath === '/api/auth/user' && req.method === 'GET') {
    const tok = extractBearerToken(req);
    if (!tok) {
      // Also check query param for legacy support
      const qsTok = qs.token || '';
      const pl2 = qsTok ? verifyMetaToken(qsTok) : null;
      if (pl2 && pl2.exp && Date.now() < pl2.exp) {
        const role = (pl2.calRole === 'superadmin') ? 'agency' : (pl2.calRole || pl2.role || 'client');
        jsonResponse(res, 200, {
          email: pl2.email || 'admin@cal.marketing',
          name: pl2.displayName || 'Agency Admin',
          initials: (pl2.displayName || 'AA').split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,2) || 'AA',
          role,
          calRole: role,
          companyId: role === 'agency' ? 'agency' : (pl2.accounts && pl2.accounts[0] ? pl2.accounts[0] : 'default'),
          accounts: pl2.accounts || [],
          title: pl2.title || ''
        });
        return;
      }
      jsonResponse(res, 401, { error: 'NO_TOKEN' });
      return;
    }
    const payload = verifyMetaToken(tok);
    if (!payload || !payload.exp || Date.now() >= payload.exp) {
      jsonResponse(res, 401, { error: 'TOKEN_EXPIRED' });
      return;
    }
    const role = (payload.calRole === 'superadmin') ? 'agency' : (payload.calRole || payload.role || 'client');
    jsonResponse(res, 200, {
      email: payload.email || '',
      name: payload.displayName || payload.email || '',
      initials: (payload.displayName || payload.email || 'U').split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,2) || 'U',
      role,
      calRole: role,
      companyId: role === 'agency' ? 'agency' : (payload.accounts && payload.accounts[0] ? payload.accounts[0] : 'default'),
      accounts: payload.accounts || [],
      title: payload.title || ''
    });
    return;
  }

  if (urlPath === '/api/auth/login' && req.method === 'POST') {
    await handleMetaLogin(req, res);
    return;
  }

  if (urlPath === '/api/meta/login' && req.method === 'POST') {
    await handleMetaLogin(req, res);
    return;
  }
  if (urlPath === '/api/meta' && req.method === 'GET') {
    await handleMetaGet(req, res, qs);
    return;
  }
  if (urlPath === '/api/meta' && req.method === 'PUT') {
    await handleMetaPut(req, res, qs);
    return;
  }

  if (urlPath === '/api/account/config' && req.method === 'GET') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const account = (qs.account || '').trim().toLowerCase();
    const features = ACCOUNT_FEATURES[account] || Object.assign({}, DEFAULT_FEATURES);
    // Merge placeId from ACCOUNT_PLACE_IDS if not already in features
    const placeInfo = ACCOUNT_PLACE_IDS[account];
    const response = Object.assign({}, features);
    if (!response.placeId && placeInfo) response.placeId = placeInfo.placeId;
    jsonResponse(res, 200, response);
    return;
  }

  if (urlPath === '/api/github/push' && req.method === 'POST') {
    const _pushToken = extractBearerToken(req);
    const _pushPayload = _pushToken ? verifyMetaToken(_pushToken) : null;
    if (!_pushPayload || (_pushPayload.role !== 'agency' && _pushPayload.role !== 'test')) {
      jsonResponse(res, 403, { error: 'FORBIDDEN' }); return;
    }
    await handleGithubPush(req, res);
    return;
  }
  if (urlPath === '/api/github/status' && req.method === 'GET') {
    const _statToken = extractBearerToken(req);
    const _statPayload = _statToken ? verifyMetaToken(_statToken) : null;
    if (!_statPayload || (_statPayload.role !== 'agency' && _statPayload.role !== 'test')) {
      jsonResponse(res, 403, { error: 'FORBIDDEN' }); return;
    }
    await handleGithubStatus(req, res);
    return;
  }

  if (urlPath === '/api/google/connect' && req.method === 'GET') { await handleGoogleConnect(res); return; }
  if (urlPath === '/api/google/callback' && req.method === 'GET') { await handleGoogleCallback(res, qs); return; }
  if (urlPath === '/api/google/status' && req.method === 'GET') { await handleGoogleStatus(res); return; }
  if (urlPath === '/api/google/disconnect' && req.method === 'POST') { await handleGoogleDisconnect(res); return; }
  if (urlPath === '/api/gbp/accounts' && req.method === 'GET') { await handleGBPAccounts(res); return; }
  if (urlPath === '/api/gbp/locations' && req.method === 'GET') { await handleGBPLocations(res, qs); return; }
  if (urlPath === '/api/gbp/reviews' && req.method === 'GET') { await handleGBPReviews(res, qs); return; }
  if (urlPath === '/api/gbp/reply' && req.method === 'POST') { await handleGBPReply(req, res); return; }
  if (urlPath === '/api/gsc/sites' && req.method === 'GET') { await handleGSCSites(res); return; }
  if (urlPath === '/api/gsc/analytics') { await handleGSCAnalytics(req, res, qs); return; }
  if (urlPath === '/api/calendar/events' && req.method === 'GET') { await handleCalendarEvents(res, qs); return; }
  if (urlPath === '/api/stripe/connect' && req.method === 'POST') { await handleStripeConnect(req, res); return; }
  if (urlPath === '/api/stripe/status' && req.method === 'GET') { await handleStripeStatus(res); return; }
  if (urlPath === '/api/stripe/revenue' && req.method === 'GET') { await handleStripeRevenue(res, qs); return; }
  if (urlPath === '/api/stripe/disconnect' && req.method === 'POST') { await handleStripeDisconnect(res); return; }

  // ── Places Reviews (no OAuth) ──
  if (urlPath === '/api/reviews/places' && req.method === 'GET') { await handlePlacesReviews(res, qs); return; }

  // ── Reviews cache write (client pushes reviews array for storage) ──
  if (urlPath === '/api/reviews/cache' && req.method === 'POST') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    try {
      const raw = await readRequestBody(req, 256 * 1024);
      const body = JSON.parse(raw.toString('utf8'));
      const acct = body.account || payload.email;
      if (!isKeyAllowed(acct, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
      const reviews = Array.isArray(body.reviews) ? body.reviews : [];
      const store = loadMetaStore();
      store['reviews_cache_' + acct] = reviews;
      if (body.meta) store['reviews_cache_meta_' + acct] = { ...body.meta, cachedAt: new Date().toISOString() };
      await saveMetaStoreQueued(store);
      jsonResponse(res, 200, { ok: true, count: reviews.length });
    } catch(e) { jsonResponse(res, 400, { error: e.message }); }
    return;
  }

    // ── Driver Management ──
  // ── Magic Link ──
  if (urlPath === '/api/auth/magic-link' && req.method === 'POST') {
    await handleMagicLinkRequest(req, res); return;
  }
  if (urlPath === '/api/auth/verify' && req.method === 'GET') {
    await handleMagicLinkVerify(req, res, qs); return;
  }

  // ── User Management (superadmin) ──
  if (urlPath === '/api/users/create-driver' && req.method === 'POST') {
    const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null;
    if (!pl) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    await handleCreateDriver(req, res, pl); return;
  }
  if (urlPath === '/api/users/create-client' && req.method === 'POST') {
    const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null;
    if (!pl) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    await handleCreateClient(req, res, pl); return;
  }
  if (urlPath === '/api/users/list' && req.method === 'GET') {
    const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null;
    if (!pl) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    await handleListUsers(req, res, pl); return;
  }
  if (urlPath === '/api/users/delete' && req.method === 'POST') {
    const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null;
    if (!pl) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    await handleDeleteUser(req, res, pl); return;
  }
  if (urlPath === '/api/users/send-onboarding' && req.method === 'POST') {
    const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null;
    if (!pl) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    await handleSendOnboardingEmail(req, res, pl); return;
  }

  if (urlPath === '/api/drivers/my-stats' && req.method === 'GET') {
    const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null;
    if (!pl) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    await handleMyDriverStats(req, res, pl); return;
  }

  // ── Driver Stats ──
  if (urlPath === '/api/drivers/stats' && req.method === 'GET') { const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null; if (!pl) { jsonResponse(res, 401, {error:'UNAUTHORIZED'}); return; } await handleDriverStats(req, res, pl); return; }

  // ── Messaging ──
  if (urlPath === '/api/messages' && req.method === 'GET') { const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null; if (!pl) { jsonResponse(res, 401, {error:'UNAUTHORIZED'}); return; } await handleMessageGet(req, res, pl); return; }
  if (urlPath === '/api/messages' && req.method === 'POST') { const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null; if (!pl) { jsonResponse(res, 401, {error:'UNAUTHORIZED'}); return; } await handleMessagePost(req, res, pl); return; }
  if (urlPath === '/api/messages/read' && req.method === 'POST') { const tok = extractBearerToken(req); const pl = tok ? verifyMetaToken(tok) : null; if (!pl) { jsonResponse(res, 401, {error:'UNAUTHORIZED'}); return; } await handleMessageRead(req, res, pl); return; }

  // ── NFC Card Registry ──
  if (urlPath === '/api/nfc/stats' && req.method === 'GET') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const acct = qs.accountId || payload.email;
    const cardName = qs.cardId || null;
    if (cardName) {
      jsonResponse(res, 200, getNfcCardStats(cardName, acct));
    } else {
      const store = loadMetaStore();
      const cards = store[`nfc_cards_${acct}`] || [];
      const all = {};
      cards.forEach(c => { all[c.name] = getNfcCardStats(c.name, acct); });
      jsonResponse(res, 200, { cards: all });
    }
    return;
  }
  // ── Home Stats (aggregated for dashboard) ──
  if (urlPath === '/api/home/stats' && req.method === 'GET') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const acct = qs.account || payload.email;
    // NFC taps
    const tapLog = path.join(__dirname, '.nfc-taps.json');
    let taps = [];
    try { taps = JSON.parse(fs.readFileSync(tapLog, 'utf8')); } catch(e) {}
    const acctTaps = taps.filter(t => t.accountId === acct);
    const now = new Date();
    const weekAgo = new Date(now - 7*24*60*60*1000).toISOString();
    const weekTaps = acctTaps.filter(t => t.ts >= weekAgo).length;
    // Reviews from store
    const store = loadMetaStore();
    const reviews = store['reviews_cache_' + acct] || [];
    const total = reviews.length;
    const avgRaw = total ? reviews.reduce((s, r) => s + (r.rating || 0), 0) / total : 0;
    const avg = avgRaw ? Math.round(avgRaw * 10) / 10 : null;
    const weekReviews = reviews.filter(r => {
      const d = r.date || r.createTime || r.time;
      if (!d) return false;
      return new Date(typeof d === 'number' ? d * 1000 : d).toISOString() >= weekAgo;
    }).length;
    const pending = reviews.filter(r => !r.reply && !r.reviewReply).length;
    jsonResponse(res, 200, {
      totalReviews: total,
      avgRating: avg,
      weekReviews,
      pendingReplies: pending,
      nfcTapsTotal: acctTaps.length,
      nfcTapsWeek: weekTaps,
    });
    return;
  }


  if (urlPath === '/api/nfc/taps' && req.method === 'GET') { await handleNfcTapsGet(req, res, qs); return; }
  if (urlPath === '/api/nfc/cards' && req.method === 'GET') { await handleNfcCardsGet(req, res, qs); return; }
  if (urlPath === '/api/nfc/cards' && req.method === 'POST') { await handleNfcCardsPost(req, res); return; }
  if (urlPath === '/api/nfc/cards' && req.method === 'DELETE') { await handleNfcCardsDelete(req, res); return; }
  if (urlPath === '/api/nfc/stats' && req.method === 'GET') { await handleNfcStats(req, res, qs); return; }
  if (urlPath === '/api/drivers/stats' && req.method === 'GET') { await handleDriversStats(req, res, qs); return; }

  // ── NFC Click Tracking ──
  if (urlPath === '/api/nfc/click' && req.method === 'POST') {
    try {
      const raw = await readRequestBody(req, 8*1024);
      const body = JSON.parse(raw.toString('utf8'));
      // Mark the most recent tap for this person as a review click
      const tapLog = path.join(__dirname, '.nfc-taps.json');
      let taps = [];
      try { taps = JSON.parse(fs.readFileSync(tapLog, 'utf8')); } catch(e) {}
      // Find last tap for this person and mark reviewClick
      for (let i = taps.length - 1; i >= 0; i--) {
        if (taps[i].person === body.person && !taps[i].reviewClick) {
          taps[i].reviewClick = true;
          break;
        }
      }
      fs.writeFileSync(tapLog, JSON.stringify(taps));
    } catch(e) {}
    jsonResponse(res, 200, { ok: true });
    return;
  }

  // ── NFC Tap Landing Page ──
  // /d/driver-name  — personal NFC landing page (short URL for cards)
  if (urlPath.startsWith('/d/')) {
    const person = decodeURIComponent(urlPath.slice(3)) || 'Your Driver';
    let reviewUrl = null;
    let resolvedAccountId = 'unknown';
    try {
      const store = loadMetaStore();
      for (const key of Object.keys(store)) {
        if (key.startsWith('nfc_cards_')) {
          const cards = store[key] || [];
          const card = cards.find(c => c.name.toLowerCase() === person.toLowerCase());
          if (card) {
            resolvedAccountId = key.replace('nfc_cards_', '');
            if (card.placeId) reviewUrl = 'https://search.google.com/local/writereview?placeid=' + card.placeId;
            else if (card.cid) reviewUrl = 'https://www.google.com/maps?cid=' + card.cid;
            break;
          }
        }
      }
    } catch(e) {}
    logNfcTap(person, resolvedAccountId, req);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(buildDriverPage(person, reviewUrl));
    return;
  }

  if (urlPath.startsWith('/tap/')) {
    const person = decodeURIComponent(urlPath.slice(5)) || 'Your Driver';
    let reviewUrl = null;
    let resolvedAccountId = 'unknown';
    try {
      const store = loadMetaStore();
      for (const key of Object.keys(store)) {
        if (key.startsWith('nfc_cards_')) {
          const cards = store[key] || [];
          const card = cards.find(c => c.name.toLowerCase() === person.toLowerCase());
          if (card) {
            resolvedAccountId = key.replace('nfc_cards_', '');
            if (card.placeId) reviewUrl = 'https://search.google.com/local/writereview?placeid=' + card.placeId;
            else if (card.cid) reviewUrl = 'https://www.google.com/maps?cid=' + card.cid;
            break;
          }
        }
      }
    } catch(e) {}
    logNfcTap(person, resolvedAccountId, req);
    const tapStats = getNfcCardStats(person, resolvedAccountId);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(buildTapPage(person, reviewUrl, tapStats));
    return;
  }

  const filePath = path.join(__dirname, 'index.html');
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(500); res.end('Error loading page'); return; }
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end(data);
  });
});

// ============ GITHUB PUSH ============
async function handleGithubStatus(req, res) {
  const pat = process.env.GITHUB_PAT;
  if (!pat) return jsonResponse(res, 200, { connected: false, reason: 'No GITHUB_PAT secret set' });
  try {
    const result = await new Promise((resolve, reject) => {
      const opts = {
        hostname: 'api.github.com',
        path: '/repos/chriskraichgit/cal-marketing-app',
        headers: { 'Authorization': 'token ' + pat, 'User-Agent': 'CAL-OS/1.0', 'Accept': 'application/vnd.github.v3+json' }
      };
      require('https').get(opts, r => {
        let d = ''; r.on('data', c => d += c); r.on('end', () => { try { resolve({ status: r.statusCode, body: JSON.parse(d) }); } catch(e) { resolve({ status: r.statusCode, body: {} }); } });
      }).on('error', reject);
    });
    if (result.status === 200) {
      return jsonResponse(res, 200, { connected: true, repo: result.body.full_name, defaultBranch: result.body.default_branch });
    }
    return jsonResponse(res, 200, { connected: false, reason: 'GitHub returned ' + result.status });
  } catch(e) { return jsonResponse(res, 200, { connected: false, reason: e.message }); }
}

async function githubApiRequest(method, apiPath, pat, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: 'api.github.com',
      path: apiPath,
      method,
      headers: {
        'Authorization': 'token ' + pat,
        'User-Agent': 'CAL-OS/1.0',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
      }
    };
    if (data) opts.headers['Content-Length'] = Buffer.byteLength(data);
    const req = require('https').request(opts, r => {
      let d = ''; r.on('data', c => d += c);
      r.on('end', () => { try { resolve({ status: r.statusCode, body: JSON.parse(d) }); } catch(e) { resolve({ status: r.statusCode, body: {} }); } });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function handleGithubPush(req, res) {
  const pat = process.env.GITHUB_PAT;
  if (!pat) return jsonResponse(res, 400, { ok: false, error: 'GITHUB_PAT secret not set.' });
  const owner = 'chriskraichgit';
  const repo = 'cal-marketing-app';
  const branch = 'main';
  try {
    // Sync full-code.html first
    fs.copyFileSync(path.join(__dirname, 'index.html'), path.join(__dirname, 'full-code.html'));

    const filesToPush = ['index.html', 'full-code.html', 'server.js'];
    const now = new Date().toISOString().replace('T', ' ').slice(0, 16);
    const commitMessage = 'CAL OS update — ' + now + ' UTC';
    const errors = [];

    for (const filename of filesToPush) {
      const filePath = path.join(__dirname, filename);
      if (!fs.existsSync(filePath)) continue;
      const content = fs.readFileSync(filePath);
      const b64 = content.toString('base64');

      const existing = await githubApiRequest('GET', '/repos/' + owner + '/' + repo + '/contents/' + filename + '?ref=' + branch, pat, null);
      const sha = existing.status === 200 ? existing.body.sha : undefined;

      const pushBody = { message: commitMessage, content: b64, branch };
      if (sha) pushBody.sha = sha;
      const result = await githubApiRequest('PUT', '/repos/' + owner + '/' + repo + '/contents/' + filename, pat, pushBody);
      if (result.status !== 200 && result.status !== 201) {
        errors.push(filename + ': ' + (result.body.message || result.status));
      }
    }

    if (errors.length) return jsonResponse(res, 500, { ok: false, error: 'Some files failed: ' + errors.join('; ') });
    return jsonResponse(res, 200, { ok: true, message: 'Pushed ' + filesToPush.length + ' files to GitHub successfully' });
  } catch(e) {
    return jsonResponse(res, 500, { ok: false, error: e.message });
  }
}

server.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}/`);
});
