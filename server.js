const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');
const { URL } = require('url');

const PORT = 5000;
const HOST = '0.0.0.0';

const TOKEN_FILE = path.join(__dirname, '.gdrive-tokens.json');
const GOOGLE_TOKEN_FILE = path.join(__dirname, '.google-tokens.json');
const META_STORE_FILE = path.join(__dirname, '.cal-meta-store.json');
const NFC_TAPS_FILE = path.join(__dirname, 'nfc_taps.json');

// ============================================================
// SERVER_USERS — Known users for server-side meta token issuance.
//
// ⚠️  SECURITY: These credentials should be loaded from environment
//     variables in production, NOT hardcoded here.
//
//     Recommended env-var approach:
//       CAL_USERS_JSON = JSON string of the full users object, OR
//       individual vars like CAL_USER_CHRIS_HASH / CAL_USER_CHRIS_ROLE
//
//     To generate a SHA-256 hash of a password:
//       node -e "const c=require('crypto');console.log(c.createHash('sha256').update('YourPassword').digest('hex'))"
//
//     Passwords are stored as SHA-256 hashes only — never plaintext.
//     Agency/test roles may access any account key; admin/user roles
//     may only access their own email key.
// ============================================================
const SERVER_USERS = process.env.CAL_USERS_JSON
  ? JSON.parse(process.env.CAL_USERS_JSON)
  : {
  'chris@cal.marketing':           { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'agency' },
  'james@cal.marketing':           { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'agency' },
  'matt@cal.marketing':            { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'agency' },
  'info@cal.marketing':            { pwHash: '7558d21cd40326eb0d89abd3d35ca3f1a207d1b6f82c07023ea49e4e42d13029', role: 'test'   },
  'client@apexlegal.com':          { pwHash: '7e166f079a275064a2118127d7102a9471f671acb67a65a2c628684606b5e11f', role: 'admin'  },
  'staff@apexlegal.com':           { pwHash: '7df64b2903b0ac2dc591ee097c36f4acdae759753bd197eaf11008093e2966ca', role: 'user'   },
  'info@unitedsewerservice.com':   { pwHash: 'c87b71ef7b9882f404028ae7d5431cc6fdb73b64cfe52e9dc0501ff3dbe1a580', role: 'admin'  },
};

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

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
  if (payload.role === 'agency' || payload.role === 'test') return true;
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

// ============ NFC TAP LOG ============
function loadNfcTaps() {
  try {
    if (fs.existsSync(NFC_TAPS_FILE)) return JSON.parse(fs.readFileSync(NFC_TAPS_FILE, 'utf8'));
  } catch (e) {}
  return [];
}

function appendNfcTap(entry) {
  try {
    const taps = loadNfcTaps();
    taps.push(entry);
    fs.writeFileSync(NFC_TAPS_FILE, JSON.stringify(taps, null, 2));
  } catch (e) { console.error('[NFC] Failed to write tap log:', e.message); }
}

// ============ ACCOUNT SLUG ============
function accountSlug(email) {
  return (email || '').toLowerCase().replace(/@/g, '_at_').replace(/\./g, '_');
}

function accountDataFile(email) {
  return path.join(__dirname, `data_${accountSlug(email)}.json`);
}

function loadAccountData(email) {
  try {
    const fp = accountDataFile(email);
    if (fs.existsSync(fp)) return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch (e) {}
  return {};
}

function saveAccountData(email, data) {
  try { fs.writeFileSync(accountDataFile(email), JSON.stringify(data, null, 2)); } catch (e) {}
}

async function handleMetaLogin(req, res) {
  let body;
  try {
    const raw = await readRequestBody(req, 64 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  const email = (body && typeof body.email === 'string') ? body.email.trim().toLowerCase() : '';
  const password = (body && typeof body.password === 'string') ? body.password : '';
  const user = SERVER_USERS[email];
  if (!user) { jsonResponse(res, 401, { error: 'INVALID_CREDENTIALS' }); return; }
  const submittedHash = crypto.createHash('sha256').update(password).digest('hex');
  const hashBuf = Buffer.from(user.pwHash, 'hex');
  const submitBuf = Buffer.from(submittedHash, 'hex');
  if (hashBuf.length !== submitBuf.length || !crypto.timingSafeEqual(hashBuf, submitBuf)) {
    jsonResponse(res, 401, { error: 'INVALID_CREDENTIALS' }); return;
  }
  const token = signMetaToken({ email, role: user.role, exp: Date.now() + TOKEN_TTL_MS });
  jsonResponse(res, 200, { token });
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
  saveMetaStore(store);
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
      r.on('end', () => { try { resolve({ status: res2.statusCode, body: JSON.parse(d) }); } catch(e) { resolve({ status: res2.statusCode, body: {} }); } });
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

// ============ NFC LANDING PAGE ============
function nfcLandingHtml(name, reviewUrl) {
  const displayName = name.charAt(0).toUpperCase() + name.slice(1);
  const safeReviewUrl = reviewUrl || `https://www.google.com/search?q=${encodeURIComponent(displayName + ' review')}`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Thanks for riding with ${displayName}!</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1b3a6b 0%,#254a83 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:24px;padding:40px 32px;max-width:420px;width:100%;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,.3)}
.logo{font-size:48px;margin-bottom:20px}
h1{font-size:28px;font-weight:800;color:#1b3a6b;line-height:1.2;margin-bottom:8px}
.sub{font-size:15px;color:#667085;margin-bottom:32px;line-height:1.5}
.review-btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:18px 24px;background:#c9a84c;color:#000;font-size:17px;font-weight:800;border-radius:14px;text-decoration:none;box-shadow:0 8px 24px rgba(201,168,76,.35);transition:transform .14s,box-shadow .14s}
.review-btn:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(201,168,76,.45)}
.star{font-size:22px}
.footer{margin-top:28px;font-size:12px;color:#98a2b3}
</style>
</head>
<body>
<div class="card">
  <div class="logo">🚗</div>
  <h1>Thank you for riding with ${displayName}!</h1>
  <p class="sub">We hope you had a great experience. Your feedback helps us improve and means a lot to our team.</p>
  <a href="${safeReviewUrl}" class="review-btn" target="_blank" rel="noopener">
    <span class="star">⭐</span> Leave a Google Review
  </a>
  <p class="footer">Powered by CAL Marketing OS</p>
</div>
</body>
</html>`;
}

// ============ REVIEW CONFIG HELPERS ============
function buildReviewUrl(placeId, cidHex) {
  if (cidHex) {
    try {
      const cidDecimal = BigInt(cidHex).toString();
      return { reviewUrl: `https://www.google.com/maps?cid=${cidDecimal}`, cidDecimal };
    } catch(e) {}
  }
  if (placeId) {
    return { reviewUrl: `https://search.google.com/local/writereview?placeid=${placeId}`, cidDecimal: null };
  }
  return { reviewUrl: null, cidDecimal: null };
}


// ============================================================
// CAL ADDITIONS SCRIPT — injected into every index.html response
// Contains: account-scoped localStorage, NFC UI, Review Config UI
// ============================================================
const _CAL_ADDITIONS_B64 = 'LyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIENBTCBPUyBBZGRpdGlvbnMg4oCUIEFjY291bnQgSXNvbGF0aW9uLCBORkMsIFJldmlldyBDb25maWcKICAgSW5qZWN0ZWQgYnkgc2VydmVyLmpzIGF0IHNlcnZlIHRpbWUKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCihmdW5jdGlvbigpIHsKICAndXNlIHN0cmljdCc7CgogIC8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogIC8vIEFDQ09VTlQtU0NPUEVEIExPQ0FMU1RPUkFHRQogIC8vIEFsbCBkYXRhIGtleXMgYXJlIHByZWZpeGVkIHdpdGggdGhlIGxvZ2dlZC1pbiBhY2NvdW50IGVtYWlsCiAgLy8gc28gc3dpdGNoaW5nIGFjY291bnRzIGF1dG9tYXRpY2FsbHkgc2NvcGVzIGFsbCBkYXRhLgogIC8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQoKICAvLyBQcmUtc2VlZCBrbm93biBhY2NvdW50cycgcmV2aWV3IGNvbmZpZ3Mgb24gZmlyc3QgbG9hZAogIGNvbnN0IEtOT1dOX1JFVklFV19DT05GSUdTID0gewogICAgJ2luZm9AdW5pdGVkc2V3ZXJzZXJ2aWNlLmNvbSc6IHsKICAgICAgY2lkSGV4OiAnMHgxNjAyYzYwMDQwYmM2Njc2JywKICAgICAgY2lkRGVjaW1hbDogJzE1ODYwNjE0MDYwNjAwMjEzNjYnLAogICAgICByZXZpZXdVcmw6ICdodHRwczovL3d3dy5nb29nbGUuY29tL21hcHM/Y2lkPTE1ODYwNjE0MDYwNjAwMjEzNjYnLAogICAgfSwKICAgIC8vIEdyZWVuIENvbGxhciBSb29maW5nIChjb25maXJtIGVtYWlsIGJlZm9yZSBhY3RpdmF0aW5nKToKICAgIC8vICdpbmZvQGdyZWVuY29sbGFycm9vZmluZy5jb20nOiB7CiAgICAvLyAgIGNpZEhleDogJzB4YjVhZGYxYjc5NjIyN2ZlZicsCiAgICAvLyAgIGNpZERlY2ltYWw6ICcxMzEwMTAxNDAxNDQ1NDQ4OTA3MScsCiAgICAvLyAgIHJldmlld1VybDogJ2h0dHBzOi8vd3d3Lmdvb2dsZS5jb20vbWFwcz9jaWQ9MTMxMDEwMTQwMTQ0NTQ0ODkwNzEnLAogICAgLy8gfSwKICB9OwoKICBmdW5jdGlvbiBnZXRDYWxBY2NvdW50KCkgewogICAgLy8gY3VycmVudFVzZXIgaXMgc2V0IGJ5IHRoZSBhcHAncyBsb2dpbiBmbG93CiAgICByZXR1cm4gKHdpbmRvdy5jdXJyZW50VXNlciB8fCB3aW5kb3cuX2NhbEN1cnJlbnRVc2VyIHx8ICcnKS50b0xvd2VyQ2FzZSgpLnRyaW0oKTsKICB9CgogIGZ1bmN0aW9uIGFjY3RLZXkoa2V5KSB7CiAgICBjb25zdCBhY2N0ID0gZ2V0Q2FsQWNjb3VudCgpOwogICAgaWYgKCFhY2N0KSByZXR1cm4ga2V5OwogICAgcmV0dXJuIGtleSArICdfXycgKyBhY2N0OwogIH0KCiAgLy8gV3JhcCBsb2NhbFN0b3JhZ2UgdG8gYmUgYWNjb3VudC1zY29wZWQgZm9yIGtub3duIENBTCBPUyBrZXlzCiAgY29uc3QgQ0FMX1NDT1BFRF9QUkVGSVhFUyA9IFsKICAgICdjYWxfbGVhZHMnLCAnY2FsX25vdGVzJywgJ2NhbF90b2RvcycsICdjYWxfY2FtcGFpZ25zJywKICAgICdjYWxfcmV2aWV3cycsICdjYWxfaW5ib3gnLCAnY2FsX2ZpbGVzJywgJ2NhbF9yZXBvcnRzJywKICAgICdjYWxfbmZjX2NvbmZpZycsICdjYWxfcmV2aWV3X2NvbmZpZycsICdjYWxfYWNjb3VudF9wcmVmcycsCiAgICAnY2FsLWxlYWRzJywgJ2NhbC1ub3RlcycsICdjYWwtdG9kb3MnLCAnY2FsLWNhbXBhaWducycsCiAgICAnY2FsLWthbmJhbicsICdjYWwtdGFza3MnLAogIF07CgogIGZ1bmN0aW9uIG5lZWRzU2NvcGUoa2V5KSB7CiAgICByZXR1cm4gQ0FMX1NDT1BFRF9QUkVGSVhFUy5zb21lKHAgPT4ga2V5LnN0YXJ0c1dpdGgocCkpOwogIH0KCiAgY29uc3QgX29yaWdHZXRJdGVtID0gU3RvcmFnZS5wcm90b3R5cGUuZ2V0SXRlbTsKICBjb25zdCBfb3JpZ1NldEl0ZW0gPSBTdG9yYWdlLnByb3RvdHlwZS5zZXRJdGVtOwogIGNvbnN0IF9vcmlnUmVtb3ZlSXRlbSA9IFN0b3JhZ2UucHJvdG90eXBlLnJlbW92ZUl0ZW07CgogIFN0b3JhZ2UucHJvdG90eXBlLmdldEl0ZW0gPSBmdW5jdGlvbihrZXkpIHsKICAgIGlmICh0aGlzID09PSBsb2NhbFN0b3JhZ2UgJiYgbmVlZHNTY29wZShrZXkpKSB7CiAgICAgIGNvbnN0IHNjb3BlZEtleSA9IGFjY3RLZXkoa2V5KTsKICAgICAgY29uc3Qgc2NvcGVkID0gX29yaWdHZXRJdGVtLmNhbGwodGhpcywgc2NvcGVkS2V5KTsKICAgICAgaWYgKHNjb3BlZCAhPT0gbnVsbCkgcmV0dXJuIHNjb3BlZDsKICAgICAgLy8gRmFsbCBiYWNrIHRvIHVuc2NvcGVkIGZvciBtaWdyYXRpb24KICAgICAgcmV0dXJuIF9vcmlnR2V0SXRlbS5jYWxsKHRoaXMsIGtleSk7CiAgICB9CiAgICByZXR1cm4gX29yaWdHZXRJdGVtLmNhbGwodGhpcywga2V5KTsKICB9OwoKICBTdG9yYWdlLnByb3RvdHlwZS5zZXRJdGVtID0gZnVuY3Rpb24oa2V5LCB2YWx1ZSkgewogICAgaWYgKHRoaXMgPT09IGxvY2FsU3RvcmFnZSAmJiBuZWVkc1Njb3BlKGtleSkpIHsKICAgICAgcmV0dXJuIF9vcmlnU2V0SXRlbS5jYWxsKHRoaXMsIGFjY3RLZXkoa2V5KSwgdmFsdWUpOwogICAgfQogICAgcmV0dXJuIF9vcmlnU2V0SXRlbS5jYWxsKHRoaXMsIGtleSwgdmFsdWUpOwogIH07CgogIFN0b3JhZ2UucHJvdG90eXBlLnJlbW92ZUl0ZW0gPSBmdW5jdGlvbihrZXkpIHsKICAgIGlmICh0aGlzID09PSBsb2NhbFN0b3JhZ2UgJiYgbmVlZHNTY29wZShrZXkpKSB7CiAgICAgIHJldHVybiBfb3JpZ1JlbW92ZUl0ZW0uY2FsbCh0aGlzLCBhY2N0S2V5KGtleSkpOwogICAgfQogICAgcmV0dXJuIF9vcmlnUmVtb3ZlSXRlbS5jYWxsKHRoaXMsIGtleSk7CiAgfTsKCiAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgLy8gTUVUQSBUT0tFTiBIRUxQRVJTIChzaGFyZWQgd2l0aCBleGlzdGluZyBhcHApCiAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgZnVuY3Rpb24gZ2V0TWV0YVRva2VuKCkgewogICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdjYWwtbWV0YS10b2tlbicpIHx8IHNlc3Npb25TdG9yYWdlLmdldEl0ZW0oJ2NhbC1tZXRhLXRva2VuJykgfHwgJyc7CiAgfQoKICBmdW5jdGlvbiBhcGlIZWFkZXJzKGV4dHJhKSB7CiAgICByZXR1cm4gT2JqZWN0LmFzc2lnbih7CiAgICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsCiAgICAgICdBdXRob3JpemF0aW9uJzogJ0JlYXJlciAnICsgZ2V0TWV0YVRva2VuKCksCiAgICB9LCBleHRyYSB8fCB7fSk7CiAgfQoKICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAvLyBSRVZJRVcgQ09ORklHIOKAlCBwcmUtc2VlZCBvbiBmaXJzdCBsb2FkCiAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgZnVuY3Rpb24gcHJlU2VlZFJldmlld0NvbmZpZ3MoKSB7CiAgICBjb25zdCB0b2tlbiA9IGdldE1ldGFUb2tlbigpOwogICAgaWYgKCF0b2tlbikgcmV0dXJuOyAvLyBub3QgbG9nZ2VkIGluIHlldAoKICAgIE9iamVjdC5rZXlzKEtOT1dOX1JFVklFV19DT05GSUdTKS5mb3JFYWNoKGZ1bmN0aW9uKGFjY291bnQpIHsKICAgICAgY29uc3QgY2ZnID0gS05PV05fUkVWSUVXX0NPTkZJR1NbYWNjb3VudF07CiAgICAgIC8vIE9ubHkgc2VlZCBpZiBub3QgYWxyZWFkeSBzYXZlZAogICAgICBmZXRjaCgnL2FwaS9yZXZpZXcvY29uZmlnP2FjY291bnQ9JyArIGVuY29kZVVSSUNvbXBvbmVudChhY2NvdW50KSwgeyBoZWFkZXJzOiBhcGlIZWFkZXJzKCkgfSkKICAgICAgICAudGhlbihmdW5jdGlvbihyKSB7IHJldHVybiByLmpzb24oKTsgfSkKICAgICAgICAudGhlbihmdW5jdGlvbihkYXRhKSB7CiAgICAgICAgICBpZiAoIWRhdGEuY29uZmlnKSB7CiAgICAgICAgICAgIC8vIFNlZWQgaXQKICAgICAgICAgICAgZmV0Y2goJy9hcGkvcmV2aWV3L2NvbmZpZycsIHsKICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICAgICAgICBoZWFkZXJzOiBhcGlIZWFkZXJzKCksCiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY2NvdW50OiBhY2NvdW50LCBjaWRIZXg6IGNmZy5jaWRIZXggfSksCiAgICAgICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCkge30pOwogICAgICAgICAgfQogICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCkge30pOwogICAgfSk7CiAgfQoKICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAvLyBORkMgU0VDVElPTiBFTkhBTkNFTUVOVFMKICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICBmdW5jdGlvbiByZW5kZXJOZmNBZGRpdGlvbnMoKSB7CiAgICBjb25zdCBuZmNTY3JlZW4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncy1uZmMnKTsKICAgIGlmICghbmZjU2NyZWVuKSByZXR1cm47CiAgICBpZiAoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NhbC1uZmMtYWRkaXRpb25zJykpIHJldHVybjsgLy8gYWxyZWFkeSBpbmplY3RlZAoKICAgIGNvbnN0IHRva2VuID0gZ2V0TWV0YVRva2VuKCk7CiAgICBjb25zdCBhZGRpdGlvbnNEaXYgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGFkZGl0aW9uc0Rpdi5pZCA9ICdjYWwtbmZjLWFkZGl0aW9ucyc7CiAgICBhZGRpdGlvbnNEaXYuc3R5bGUubWFyZ2luVG9wID0gJzI0cHgnOwoKICAgIGFkZGl0aW9uc0Rpdi5pbm5lckhUTUwgPSBgCjxkaXYgY2xhc3M9ImNhcmQgY2FyZC1wYWQiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjE0cHgiPgogIDxkaXYgY2xhc3M9ImNhcmQtaGVhZCI+CiAgICA8c3BhbiBjbGFzcz0iY2FyZC10aXRsZSI+TkZDIFJldmlldyBVUkwgQ29uZmlnPC9zcGFuPgogIDwvZGl2PgogIDxwIHN0eWxlPSJmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS1tdXRlZCk7bWFyZ2luLWJvdHRvbToxNHB4Ij5TZXQgdGhlIEdvb2dsZSBSZXZpZXcgVVJMIGVhY2ggTkZDIGNhcmQgcmVkaXJlY3RzIHRvLiBMZWF2ZSBibGFuayB0byB1c2UgdGhlIGFjY291bnQgcmV2aWV3IFVSTC48L3A+CiAgPGRpdiBzdHlsZT0iZGlzcGxheTpncmlkO2dhcDoxMHB4Ij4KICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6Z3JpZDtnYXA6NnB4Ij4KICAgICAgPGxhYmVsIHN0eWxlPSJmb250LXNpemU6MTJweDtmb250LXdlaWdodDo4MDA7Y29sb3I6dmFyKC0tbXV0ZWQpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouMDRlbSI+TmFtZSAoZS5nLiBqYW1lcywgY2hyaXMpPC9sYWJlbD4KICAgICAgPGlucHV0IGlkPSJuZmMtdXJsLW5hbWUiIGNsYXNzPSJpbnB1dC1zdGQiIHBsYWNlaG9sZGVyPSJqYW1lcyIgc3R5bGU9ImhlaWdodDo0MHB4Ij4KICAgIDwvZGl2PgogICAgPGRpdiBzdHlsZT0iZGlzcGxheTpncmlkO2dhcDo2cHgiPgogICAgICA8bGFiZWwgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjgwMDtjb2xvcjp2YXIoLS1tdXRlZCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOi4wNGVtIj5Hb29nbGUgUmV2aWV3IFVSTDwvbGFiZWw+CiAgICAgIDxpbnB1dCBpZD0ibmZjLXVybC12YWx1ZSIgY2xhc3M9ImlucHV0LXN0ZCIgcGxhY2Vob2xkZXI9Imh0dHBzOi8vd3d3Lmdvb2dsZS5jb20vbWFwcz9jaWQ9Li4uIiBzdHlsZT0iaGVpZ2h0OjQwcHgiPgogICAgPC9kaXY+CiAgICA8YnV0dG9uIG9uY2xpY2s9ImNhbFNhdmVOZmNSZXZpZXdVcmwoKSIgY2xhc3M9ImJ0bi1wcmltYXJ5IiBzdHlsZT0id2lkdGg6YXV0bztoZWlnaHQ6MzhweDtwYWRkaW5nOjAgMjBweDtib3JkZXItcmFkaXVzOjEwcHgiPlNhdmUgTkZDIFVSTDwvYnV0dG9uPgogICAgPGRpdiBpZD0ibmZjLXVybC1zdGF0dXMiIHN0eWxlPSJmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7ZGlzcGxheTpub25lIj48L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8ZGl2IGNsYXNzPSJjYXJkIiBzdHlsZT0ibWFyZ2luLWJvdHRvbToxNHB4Ij4KICA8ZGl2IGNsYXNzPSJjYXJkLXBhZCIgc3R5bGU9InBhZGRpbmctYm90dG9tOjhweCI+CiAgICA8ZGl2IGNsYXNzPSJjYXJkLWhlYWQiPgogICAgICA8c3BhbiBjbGFzcz0iY2FyZC10aXRsZSI+TkZDIFRhcCBMb2c8L3NwYW4+CiAgICAgIDxidXR0b24gb25jbGljaz0iY2FsTG9hZE5mY1RhcHMoKSIgY2xhc3M9ImJ0bi12aWV3IiBzdHlsZT0iaGVpZ2h0OjMwcHgiPlJlZnJlc2g8L2J1dHRvbj4KICAgIDwvZGl2PgogIDwvZGl2PgogIDxkaXYgY2xhc3M9Im5mYy10YWJsZS13cmFwIj4KICAgIDx0YWJsZSBjbGFzcz0idGJsIiBpZD0ibmZjLXRhcC10YWJsZSI+CiAgICAgIDx0aGVhZD4KICAgICAgICA8dHI+CiAgICAgICAgICA8dGg+TmFtZTwvdGg+CiAgICAgICAgICA8dGg+VGltZTwvdGg+CiAgICAgICAgICA8dGg+VXNlciBBZ2VudDwvdGg+CiAgICAgICAgPC90cj4KICAgICAgPC90aGVhZD4KICAgICAgPHRib2R5IGlkPSJuZmMtdGFwLXRib2R5Ij4KICAgICAgICA8dHI+PHRkIGNvbHNwYW49IjMiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjp2YXIoLS1tdXRlZCk7cGFkZGluZzoyMHB4Ij5DbGljayBSZWZyZXNoIHRvIGxvYWQgdGFwIGxvZzwvdGQ+PC90cj4KICAgICAgPC90Ym9keT4KICAgIDwvdGFibGU+CiAgPC9kaXY+CjwvZGl2PgpgOwogICAgbmZjU2NyZWVuLmFwcGVuZENoaWxkKGFkZGl0aW9uc0Rpdik7CiAgfQoKICB3aW5kb3cuY2FsU2F2ZU5mY1Jldmlld1VybCA9IGZ1bmN0aW9uKCkgewogICAgY29uc3QgbmFtZSA9IChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbmZjLXVybC1uYW1lJykgfHwge30pLnZhbHVlIHx8ICcnOwogICAgY29uc3QgdXJsID0gKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCduZmMtdXJsLXZhbHVlJykgfHwge30pLnZhbHVlIHx8ICcnOwogICAgY29uc3Qgc3RhdHVzRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbmZjLXVybC1zdGF0dXMnKTsKICAgIGlmICghbmFtZSB8fCAhdXJsKSB7CiAgICAgIGlmIChzdGF0dXNFbCkgeyBzdGF0dXNFbC50ZXh0Q29udGVudCA9ICdQbGVhc2UgZmlsbCBpbiBib3RoIG5hbWUgYW5kIFVSTC4nOyBzdGF0dXNFbC5zdHlsZS5jb2xvciA9ICd2YXIoLS1yZWQpJzsgc3RhdHVzRWwuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7IH0KICAgICAgcmV0dXJuOwogICAgfQogICAgZmV0Y2goJy9hcGkvbmZjL3NldC1yZXZpZXctdXJsJywgewogICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgaGVhZGVyczogYXBpSGVhZGVycygpLAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IG5hbWU6IG5hbWUudHJpbSgpLnRvTG93ZXJDYXNlKCksIHJldmlld1VybDogdXJsLnRyaW0oKSB9KSwKICAgIH0pLnRoZW4oZnVuY3Rpb24ocikgeyByZXR1cm4gci5qc29uKCk7IH0pLnRoZW4oZnVuY3Rpb24oZCkgewogICAgICBpZiAoZC5vaykgewogICAgICAgIGlmIChzdGF0dXNFbCkgeyBzdGF0dXNFbC50ZXh0Q29udGVudCA9ICdTYXZlZCEgTkZDIHRhcCBmb3IgIicgKyBkLm5hbWUgKyAnIiB3aWxsIG5vdyByZWRpcmVjdCB0bzogJyArIGQucmV2aWV3VXJsOyBzdGF0dXNFbC5zdHlsZS5jb2xvciA9ICd2YXIoLS1ncmVlbiknOyBzdGF0dXNFbC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgfQogICAgICB9IGVsc2UgewogICAgICAgIGlmIChzdGF0dXNFbCkgeyBzdGF0dXNFbC50ZXh0Q29udGVudCA9ICdFcnJvcjogJyArIChkLmVycm9yIHx8ICdVbmtub3duIGVycm9yJyk7IHN0YXR1c0VsLnN0eWxlLmNvbG9yID0gJ3ZhcigtLXJlZCknOyBzdGF0dXNFbC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgfQogICAgICB9CiAgICB9KS5jYXRjaChmdW5jdGlvbihlKSB7CiAgICAgIGlmIChzdGF0dXNFbCkgeyBzdGF0dXNFbC50ZXh0Q29udGVudCA9ICdOZXR3b3JrIGVycm9yOiAnICsgZS5tZXNzYWdlOyBzdGF0dXNFbC5zdHlsZS5jb2xvciA9ICd2YXIoLS1yZWQpJzsgc3RhdHVzRWwuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7IH0KICAgIH0pOwogIH07CgogIHdpbmRvdy5jYWxMb2FkTmZjVGFwcyA9IGZ1bmN0aW9uKCkgewogICAgY29uc3QgdGJvZHkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbmZjLXRhcC10Ym9keScpOwogICAgaWYgKCF0Ym9keSkgcmV0dXJuOwogICAgdGJvZHkuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iMyIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyO2NvbG9yOnZhcigtLW11dGVkKTtwYWRkaW5nOjIwcHgiPkxvYWRpbmcuLi48L3RkPjwvdHI+JzsKICAgIGZldGNoKCcvYXBpL25mYy90YXBzJywgeyBoZWFkZXJzOiBhcGlIZWFkZXJzKCkgfSkKICAgICAgLnRoZW4oZnVuY3Rpb24ocikgeyByZXR1cm4gci5qc29uKCk7IH0pCiAgICAgIC50aGVuKGZ1bmN0aW9uKGRhdGEpIHsKICAgICAgICBjb25zdCB0YXBzID0gKGRhdGEudGFwcyB8fCBbXSkuc2xpY2UoKS5yZXZlcnNlKCk7CiAgICAgICAgaWYgKCF0YXBzLmxlbmd0aCkgewogICAgICAgICAgdGJvZHkuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iMyIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyO2NvbG9yOnZhcigtLW11dGVkKTtwYWRkaW5nOjIwcHgiPk5vIHRhcHMgcmVjb3JkZWQgeWV0PC90ZD48L3RyPic7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIHRib2R5LmlubmVySFRNTCA9IHRhcHMubWFwKGZ1bmN0aW9uKHQpIHsKICAgICAgICAgIGNvbnN0IHVhID0gKHQudXNlckFnZW50IHx8ICcnKS5zbGljZSgwLCA2MCkgKyAodC51c2VyQWdlbnQgJiYgdC51c2VyQWdlbnQubGVuZ3RoID4gNjAgPyAn4oCmJyA6ICcnKTsKICAgICAgICAgIGNvbnN0IHRzID0gdC50aW1lc3RhbXAgPyBuZXcgRGF0ZSh0LnRpbWVzdGFtcCkudG9Mb2NhbGVTdHJpbmcoKSA6ICcnOwogICAgICAgICAgcmV0dXJuICc8dHI+PHRkIHN0eWxlPSJmb250LXdlaWdodDo4MDAiPicgKyAodC5uYW1lIHx8ICcnKSArICc8L3RkPjx0ZD4nICsgdHMgKyAnPC90ZD48dGQgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dGVkKSI+JyArIHVhICsgJzwvdGQ+PC90cj4nOwogICAgICAgIH0pLmpvaW4oJycpOwogICAgICB9KS5jYXRjaChmdW5jdGlvbihlKSB7CiAgICAgICAgdGJvZHkuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iMyIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyO2NvbG9yOnZhcigtLXJlZCk7cGFkZGluZzoyMHB4Ij5FcnJvcjogJyArIGUubWVzc2FnZSArICc8L3RkPjwvdHI+JzsKICAgICAgfSk7CiAgfTsKCiAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgLy8gUkVWSUVXIENPTkZJRyBTRUNUSU9OIEVOSEFOQ0VNRU5UUwogIC8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogIGZ1bmN0aW9uIHJlbmRlclJldmlld0NvbmZpZ1BhbmVsKCkgewogICAgLy8gVHJ5IG11bHRpcGxlIGtub3duIElEcyBmb3IgdGhlIHJldmlld3Mgc2NyZWVuCiAgICBjb25zdCByZXZpZXdTY3JlZW4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncy1yZXZpZXdzJykgfHwgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3MtcmVwdXRhdGlvbicpIHx8IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzLXJldmlldycpOwogICAgaWYgKCFyZXZpZXdTY3JlZW4pIHJldHVybjsKICAgIGlmIChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2FsLXJldmlldy1jb25maWctcGFuZWwnKSkgcmV0dXJuOwoKICAgIGNvbnN0IHBhbmVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBwYW5lbC5pZCA9ICdjYWwtcmV2aWV3LWNvbmZpZy1wYW5lbCc7CiAgICBwYW5lbC5zdHlsZS5tYXJnaW5Cb3R0b20gPSAnMjBweCc7CgogICAgY29uc3QgYWNjb3VudCA9IGdldENhbEFjY291bnQoKTsKCiAgICBwYW5lbC5pbm5lckhUTUwgPSBgCjxkaXYgY2xhc3M9ImNhcmQgY2FyZC1wYWQiPgogIDxkaXYgY2xhc3M9ImNhcmQtaGVhZCI+CiAgICA8c3BhbiBjbGFzcz0iY2FyZC10aXRsZSI+R29vZ2xlIFJldmlldyBMaW5rPC9zcGFuPgogIDwvZGl2PgogIDxwIHN0eWxlPSJmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS1tdXRlZCk7bWFyZ2luLWJvdHRvbToxNnB4Ij5Db25maWd1cmUgeW91ciBHb29nbGUgcmV2aWV3IGxpbmsuIFN0YWZmIGNhbiBjb3B5IGFuZCBzaGFyZSBpdCB0byBjb2xsZWN0IG1vcmUgcmV2aWV3cy48L3A+CgogIDxkaXYgc3R5bGU9ImRpc3BsYXk6Z3JpZDtnYXA6MTBweDttYXJnaW4tYm90dG9tOjE2cHgiPgogICAgPGRpdiBzdHlsZT0iZGlzcGxheTpncmlkO2dhcDo2cHgiPgogICAgICA8bGFiZWwgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjgwMDtjb2xvcjp2YXIoLS1tdXRlZCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOi4wNGVtIj5Hb29nbGUgUGxhY2UgSUQ8L2xhYmVsPgogICAgICA8aW5wdXQgaWQ9InJ2LXBsYWNlLWlkIiBjbGFzcz0iaW5wdXQtc3RkIiBwbGFjZWhvbGRlcj0iQ2hJSi4uLiIgc3R5bGU9ImhlaWdodDo0MHB4Ij4KICAgICAgPHNwYW4gc3R5bGU9ImZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dGVkMikiPkZpbmQgaW4gR29vZ2xlIE1hcHMg4oaSIFNoYXJlIOKGkiBFbWJlZCDihpIgUGxhY2UgSUQuIEZvcm1hdDogQ2hJSi4uLjwvc3Bhbj4KICAgIDwvZGl2PgogICAgPGRpdiBzdHlsZT0iZGlzcGxheTpncmlkO2dhcDo2cHgiPgogICAgICA8bGFiZWwgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjgwMDtjb2xvcjp2YXIoLS1tdXRlZCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOi4wNGVtIj5Hb29nbGUgQ0lEIChoZXgsIGZyb20gTWFwcyBVUkwpPC9sYWJlbD4KICAgICAgPGlucHV0IGlkPSJydi1jaWQtaGV4IiBjbGFzcz0iaW5wdXQtc3RkIiBwbGFjZWhvbGRlcj0iMHgxNjAyYzYwMDQwYmM2Njc2IiBzdHlsZT0iaGVpZ2h0OjQwcHgiPgogICAgICA8c3BhbiBzdHlsZT0iZm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tbXV0ZWQyKSI+RnJvbSBHb29nbGUgTWFwcyBVUkw6ID9jaWQ9MTIzNC4uLiBvciBoZXggZm9ybWF0IDB4Li4uIENJRCBnaXZlcyBhIGRpcmVjdCByZXZpZXcgbGluay4gVGFrZXMgcHJpb3JpdHkgb3ZlciBQbGFjZSBJRC48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxidXR0b24gb25jbGljaz0iY2FsU2F2ZVJldmlld0NvbmZpZygpIiBjbGFzcz0iYnRuLXByaW1hcnkiIHN0eWxlPSJ3aWR0aDphdXRvO2hlaWdodDozOHB4O3BhZGRpbmc6MCAyMHB4O2JvcmRlci1yYWRpdXM6MTBweCI+U2F2ZSAmIEdlbmVyYXRlIExpbms8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBpZD0icnYtbGluay1kaXNwbGF5IiBzdHlsZT0iZGlzcGxheTpub25lO3BhZGRpbmc6MTRweDtiYWNrZ3JvdW5kOnZhcigtLXBhZ2UpO2JvcmRlci1yYWRpdXM6MTBweDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcikiPgogICAgPGRpdiBzdHlsZT0iZm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6OTAwO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouMDZlbTtjb2xvcjp2YXIoLS1tdXRlZCk7bWFyZ2luLWJvdHRvbTo4cHgiPllvdXIgR29vZ2xlIFJldmlldyBMaW5rPC9kaXY+CiAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHgiPgogICAgICA8YSBpZD0icnYtbGluay1hbmNob3IiIGhyZWY9IiMiIHRhcmdldD0iX2JsYW5rIiByZWw9Im5vb3BlbmVyIgogICAgICAgICBzdHlsZT0iZmxleDoxO2ZvbnQtc2l6ZToxM3B4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS1ibHVlKTt3b3JkLWJyZWFrOmJyZWFrLWFsbDt0ZXh0LWRlY29yYXRpb246dW5kZXJsaW5lIj48L2E+CiAgICAgIDxidXR0b24gb25jbGljaz0iY2FsQ29weVJldmlld0xpbmsoKSIgY2xhc3M9ImJ0bi12aWV3IiBzdHlsZT0id2hpdGUtc3BhY2U6bm93cmFwO2ZsZXgtc2hyaW5rOjAiPkNvcHk8L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGRpdiBzdHlsZT0ibWFyZ2luLXRvcDoxMHB4O2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dGVkKSI+U2hhcmUgdGhpcyBsaW5rIHdpdGggY3VzdG9tZXJzIHZpYSB0ZXh0LCBlbWFpbCwgb3IgTkZDIGNhcmQuIENsaWNraW5nIGl0IG9wZW5zIHRoZSBHb29nbGUgcmV2aWV3IGZvcm0gZGlyZWN0bHkuPC9kaXY+CiAgPC9kaXY+CiAgPGRpdiBpZD0icnYtY29uZmlnLXN0YXR1cyIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDttYXJnaW4tdG9wOjhweDtkaXNwbGF5Om5vbmUiPjwvZGl2Pgo8L2Rpdj4KYDsKCiAgICAvLyBJbnNlcnQgYXQgdGhlIHRvcCBvZiB0aGUgcmV2aWV3IHNjcmVlbgogICAgcmV2aWV3U2NyZWVuLmluc2VydEJlZm9yZShwYW5lbCwgcmV2aWV3U2NyZWVuLmZpcnN0Q2hpbGQpOwoKICAgIC8vIExvYWQgZXhpc3RpbmcgY29uZmlnCiAgICBjYWxMb2FkUmV2aWV3Q29uZmlnKCk7CiAgfQoKICB3aW5kb3cuY2FsTG9hZFJldmlld0NvbmZpZyA9IGZ1bmN0aW9uKCkgewogICAgY29uc3QgYWNjb3VudCA9IGdldENhbEFjY291bnQoKTsKICAgIGlmICghYWNjb3VudCkgcmV0dXJuOwogICAgZmV0Y2goJy9hcGkvcmV2aWV3L2NvbmZpZz9hY2NvdW50PScgKyBlbmNvZGVVUklDb21wb25lbnQoYWNjb3VudCksIHsgaGVhZGVyczogYXBpSGVhZGVycygpIH0pCiAgICAgIC50aGVuKGZ1bmN0aW9uKHIpIHsgcmV0dXJuIHIuanNvbigpOyB9KQogICAgICAudGhlbihmdW5jdGlvbihkYXRhKSB7CiAgICAgICAgaWYgKGRhdGEuY29uZmlnICYmIGRhdGEuY29uZmlnLnJldmlld1VybCkgewogICAgICAgICAgY2FsU2hvd1Jldmlld0xpbmsoZGF0YS5jb25maWcucmV2aWV3VXJsKTsKICAgICAgICAgIGlmIChkYXRhLmNvbmZpZy5wbGFjZUlkICYmIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdydi1wbGFjZS1pZCcpKSB7CiAgICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdydi1wbGFjZS1pZCcpLnZhbHVlID0gZGF0YS5jb25maWcucGxhY2VJZDsKICAgICAgICAgIH0KICAgICAgICAgIGlmIChkYXRhLmNvbmZpZy5jaWRIZXggJiYgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3J2LWNpZC1oZXgnKSkgewogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncnYtY2lkLWhleCcpLnZhbHVlID0gZGF0YS5jb25maWcuY2lkSGV4OwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSkuY2F0Y2goZnVuY3Rpb24oKSB7fSk7CiAgfTsKCiAgd2luZG93LmNhbFNhdmVSZXZpZXdDb25maWcgPSBmdW5jdGlvbigpIHsKICAgIGNvbnN0IGFjY291bnQgPSBnZXRDYWxBY2NvdW50KCk7CiAgICBjb25zdCBwbGFjZUlkID0gKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdydi1wbGFjZS1pZCcpIHx8IHt9KS52YWx1ZSB8fCAnJzsKICAgIGNvbnN0IGNpZEhleCA9IChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncnYtY2lkLWhleCcpIHx8IHt9KS52YWx1ZSB8fCAnJzsKICAgIGNvbnN0IHN0YXR1c0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3J2LWNvbmZpZy1zdGF0dXMnKTsKCiAgICBpZiAoIWFjY291bnQpIHsKICAgICAgaWYgKHN0YXR1c0VsKSB7IHN0YXR1c0VsLnRleHRDb250ZW50ID0gJ05vdCBsb2dnZWQgaW4uJzsgc3RhdHVzRWwuc3R5bGUuY29sb3IgPSAndmFyKC0tcmVkKSc7IHN0YXR1c0VsLnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOyB9CiAgICAgIHJldHVybjsKICAgIH0KICAgIGlmICghcGxhY2VJZCAmJiAhY2lkSGV4KSB7CiAgICAgIGlmIChzdGF0dXNFbCkgeyBzdGF0dXNFbC50ZXh0Q29udGVudCA9ICdQbGVhc2UgZW50ZXIgYSBQbGFjZSBJRCBvciBDSUQgaGV4IHZhbHVlLic7IHN0YXR1c0VsLnN0eWxlLmNvbG9yID0gJ3ZhcigtLXJlZCknOyBzdGF0dXNFbC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgfQogICAgICByZXR1cm47CiAgICB9CgogICAgZmV0Y2goJy9hcGkvcmV2aWV3L2NvbmZpZycsIHsKICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgIGhlYWRlcnM6IGFwaUhlYWRlcnMoKSwKICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY2NvdW50OiBhY2NvdW50LCBwbGFjZUlkOiBwbGFjZUlkIHx8IG51bGwsIGNpZEhleDogY2lkSGV4IHx8IG51bGwgfSksCiAgICB9KS50aGVuKGZ1bmN0aW9uKHIpIHsgcmV0dXJuIHIuanNvbigpOyB9KS50aGVuKGZ1bmN0aW9uKGQpIHsKICAgICAgaWYgKGQub2sgJiYgZC5jb25maWcgJiYgZC5jb25maWcucmV2aWV3VXJsKSB7CiAgICAgICAgY2FsU2hvd1Jldmlld0xpbmsoZC5jb25maWcucmV2aWV3VXJsKTsKICAgICAgICBpZiAoc3RhdHVzRWwpIHsgc3RhdHVzRWwudGV4dENvbnRlbnQgPSAnU2F2ZWQhJzsgc3RhdHVzRWwuc3R5bGUuY29sb3IgPSAndmFyKC0tZ3JlZW4pJzsgc3RhdHVzRWwuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7IH0KICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkgeyBpZiAoc3RhdHVzRWwpIHN0YXR1c0VsLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7IH0sIDMwMDApOwogICAgICB9IGVsc2UgewogICAgICAgIGlmIChzdGF0dXNFbCkgeyBzdGF0dXNFbC50ZXh0Q29udGVudCA9ICdFcnJvcjogJyArIChkLmVycm9yIHx8ICdVbmtub3duIGVycm9yJyk7IHN0YXR1c0VsLnN0eWxlLmNvbG9yID0gJ3ZhcigtLXJlZCknOyBzdGF0dXNFbC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgfQogICAgICB9CiAgICB9KS5jYXRjaChmdW5jdGlvbihlKSB7CiAgICAgIGlmIChzdGF0dXNFbCkgeyBzdGF0dXNFbC50ZXh0Q29udGVudCA9ICdOZXR3b3JrIGVycm9yOiAnICsgZS5tZXNzYWdlOyBzdGF0dXNFbC5zdHlsZS5jb2xvciA9ICd2YXIoLS1yZWQpJzsgc3RhdHVzRWwuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7IH0KICAgIH0pOwogIH07CgogIGZ1bmN0aW9uIGNhbFNob3dSZXZpZXdMaW5rKHVybCkgewogICAgY29uc3QgZGlzcGxheSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdydi1saW5rLWRpc3BsYXknKTsKICAgIGNvbnN0IGFuY2hvciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdydi1saW5rLWFuY2hvcicpOwogICAgaWYgKGRpc3BsYXkpIGRpc3BsYXkuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CiAgICBpZiAoYW5jaG9yKSB7IGFuY2hvci5ocmVmID0gdXJsOyBhbmNob3IudGV4dENvbnRlbnQgPSB1cmw7IH0KICB9CgogIHdpbmRvdy5jYWxDb3B5UmV2aWV3TGluayA9IGZ1bmN0aW9uKCkgewogICAgY29uc3QgYW5jaG9yID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3J2LWxpbmstYW5jaG9yJyk7CiAgICBpZiAoIWFuY2hvciB8fCAhYW5jaG9yLmhyZWYgfHwgYW5jaG9yLmhyZWYgPT09ICcjJykgcmV0dXJuOwogICAgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoYW5jaG9yLmhyZWYpLnRoZW4oZnVuY3Rpb24oKSB7CiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ1tvbmNsaWNrPSJjYWxDb3B5UmV2aWV3TGluaygpIl0nKTsKICAgICAgaWYgKGJ0bikgeyBjb25zdCBvcmlnID0gYnRuLnRleHRDb250ZW50OyBidG4udGV4dENvbnRlbnQgPSAnQ29waWVkISc7IHNldFRpbWVvdXQoZnVuY3Rpb24oKSB7IGJ0bi50ZXh0Q29udGVudCA9IG9yaWc7IH0sIDIwMDApOyB9CiAgICB9KS5jYXRjaChmdW5jdGlvbigpIHsKICAgICAgY29uc3QgdGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCd0ZXh0YXJlYScpOwogICAgICB0YS52YWx1ZSA9IGFuY2hvci5ocmVmOwogICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHRhKTsKICAgICAgdGEuc2VsZWN0KCk7CiAgICAgIGRvY3VtZW50LmV4ZWNDb21tYW5kKCdjb3B5Jyk7CiAgICAgIGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQodGEpOwogICAgfSk7CiAgfTsKCiAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgLy8gSE9PSyBJTlRPIEFQUCBOQVYgLyBBQ0NPVU5UIFNXSVRDSEVTCiAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgZnVuY3Rpb24gb25DYWxOYXZDaGFuZ2Uoc2NyZWVuSWQpIHsKICAgIGlmIChzY3JlZW5JZCA9PT0gJ25mYycpIHsKICAgICAgc2V0VGltZW91dChmdW5jdGlvbigpIHsgcmVuZGVyTmZjQWRkaXRpb25zKCk7IH0sIDEwMCk7CiAgICB9CiAgICBpZiAoc2NyZWVuSWQgPT09ICdyZXZpZXdzJyB8fCBzY3JlZW5JZCA9PT0gJ3JlcHV0YXRpb24nIHx8IHNjcmVlbklkID09PSAncmV2aWV3JykgewogICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkgeyByZW5kZXJSZXZpZXdDb25maWdQYW5lbCgpOyB9LCAxMDApOwogICAgfQogIH0KCiAgLy8gV3JhcCB3aW5kb3cubmF2IGlmIGl0IGV4aXN0cwogIHZhciBfb3JpZ05hdiA9IHdpbmRvdy5uYXY7CiAgd2luZG93Lm5hdiA9IGZ1bmN0aW9uKGlkKSB7CiAgICB2YXIgcmVzdWx0ID0gX29yaWdOYXYgPyBfb3JpZ05hdihpZCkgOiB1bmRlZmluZWQ7CiAgICBvbkNhbE5hdkNoYW5nZShpZCk7CiAgICByZXR1cm4gcmVzdWx0OwogIH07CgogIC8vIEFsc28gbGlzdGVuIGZvciBhY2NvdW50IGNoYW5nZXMg4oCUIHJlLXJlbmRlciBVSSB3aGVuIGFjY291bnQgc3dpdGNoZXMKICB2YXIgX3ByZXZDYWxBY2NvdW50ID0gJyc7CiAgc2V0SW50ZXJ2YWwoZnVuY3Rpb24oKSB7CiAgICB2YXIgY3VycmVudCA9IGdldENhbEFjY291bnQoKTsKICAgIGlmIChjdXJyZW50ICYmIGN1cnJlbnQgIT09IF9wcmV2Q2FsQWNjb3VudCkgewogICAgICBfcHJldkNhbEFjY291bnQgPSBjdXJyZW50OwogICAgICAvLyBSZS1yZW5kZXIgYWRkaXRpb25zIGZvciBjdXJyZW50IHNjcmVlbgogICAgICB2YXIgYWN0aXZlU2NyZWVuID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLnNjcmVlbi5hY3RpdmUnKTsKICAgICAgaWYgKGFjdGl2ZVNjcmVlbikgewogICAgICAgIHZhciBpZCA9IGFjdGl2ZVNjcmVlbi5pZCA/IGFjdGl2ZVNjcmVlbi5pZC5yZXBsYWNlKCdzLScsICcnKSA6ICcnOwogICAgICAgIG9uQ2FsTmF2Q2hhbmdlKGlkKTsKICAgICAgfQogICAgICAvLyBQcmUtc2VlZCByZXZpZXcgY29uZmlncyBmb3IgdGhpcyBhY2NvdW50CiAgICAgIHByZVNlZWRSZXZpZXdDb25maWdzKCk7CiAgICB9CiAgfSwgMTAwMCk7CgogIC8vIFJ1biBvbiBET01Db250ZW50TG9hZGVkCiAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsIGZ1bmN0aW9uKCkgewogICAgLy8gVHJ5IHRvIGluamVjdCBvbiBjdXJyZW50IHNjcmVlbgogICAgc2V0VGltZW91dChmdW5jdGlvbigpIHsKICAgICAgdmFyIGFjdGl2ZVNjcmVlbiA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy5zY3JlZW4uYWN0aXZlJyk7CiAgICAgIGlmIChhY3RpdmVTY3JlZW4pIHsKICAgICAgICB2YXIgaWQgPSBhY3RpdmVTY3JlZW4uaWQgPyBhY3RpdmVTY3JlZW4uaWQucmVwbGFjZSgncy0nLCAnJykgOiAnJzsKICAgICAgICBvbkNhbE5hdkNoYW5nZShpZCk7CiAgICAgIH0KICAgICAgcHJlU2VlZFJldmlld0NvbmZpZ3MoKTsKICAgIH0sIDIwMDApOwogIH0pOwoKICAvLyBBbHNvIHRyeSBpbW1lZGlhdGVseSBpZiBET00gaXMgYWxyZWFkeSBsb2FkZWQKICBpZiAoZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2NvbXBsZXRlJyB8fCBkb2N1bWVudC5yZWFkeVN0YXRlID09PSAnaW50ZXJhY3RpdmUnKSB7CiAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkgewogICAgICBwcmVTZWVkUmV2aWV3Q29uZmlncygpOwogICAgfSwgMjUwMCk7CiAgfQoKICBjb25zb2xlLmxvZygnW0NBTCBBZGRpdGlvbnNdIExvYWRlZDogYWNjb3VudCBpc29sYXRpb24sIE5GQywgcmV2aWV3IGNvbmZpZycpOwp9KSgpOwo=';
const _CAL_ADDITIONS_SCRIPT = '<script>' + Buffer.from(_CAL_ADDITIONS_B64, 'base64').toString('utf8') + '<\/script>';

function injectCalAdditions(html) {
  const closeBody = '</body>';
  const idx = html.lastIndexOf(closeBody);
  if (idx === -1) return html + _CAL_ADDITIONS_SCRIPT;
  return html.slice(0, idx) + _CAL_ADDITIONS_SCRIPT + html.slice(idx);
}

const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];
  const qs = parseQueryString(req.url);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ============ NFC TAP LANDING PAGE ============
  // GET /tap/:name — public, no auth required
  if (req.method === 'GET' && urlPath.startsWith('/tap/')) {
    const name = decodeURIComponent(urlPath.slice(5)).toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (!name) { res.writeHead(404); res.end('Not found'); return; }

    // Log the tap
    const tapEntry = {
      name,
      timestamp: new Date().toISOString(),
      userAgent: req.headers['user-agent'] || '',
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
    };
    appendNfcTap(tapEntry);
    console.log(`[NFC] Tap logged for: ${name}`);

    // Get review URL from meta store
    const store = loadMetaStore();
    const reviewUrl = store[`nfc_review_url_${name}`] || null;

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(nfcLandingHtml(name, reviewUrl));
    return;
  }

  // ============ NFC API: get tap log ============
  // GET /api/nfc/taps — requires Bearer token
  if (urlPath === '/api/nfc/taps' && req.method === 'GET') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const taps = loadNfcTaps();
    jsonResponse(res, 200, { taps });
    return;
  }

  // ============ NFC API: set review URL ============
  // POST /api/nfc/set-review-url — requires Bearer token
  if (urlPath === '/api/nfc/set-review-url' && req.method === 'POST') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    let body;
    try { const raw = await readRequestBody(req, 64 * 1024); body = JSON.parse(raw.toString('utf8')); } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
    const { name, reviewUrl } = body || {};
    if (!name || !reviewUrl) { jsonResponse(res, 400, { error: 'MISSING_FIELDS', required: ['name', 'reviewUrl'] }); return; }
    const safeName = String(name).toLowerCase().replace(/[^a-z0-9_-]/g, '');
    const store = loadMetaStore();
    store[`nfc_review_url_${safeName}`] = reviewUrl;
    saveMetaStore(store);
    jsonResponse(res, 200, { ok: true, name: safeName, reviewUrl });
    return;
  }

  // ============ REVIEW CONFIG: get ============
  // GET /api/review/config?account=EMAIL
  if (urlPath === '/api/review/config' && req.method === 'GET') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const account = qs.account;
    if (!account) { jsonResponse(res, 400, { error: 'MISSING_ACCOUNT' }); return; }
    if (!isKeyAllowed(account, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
    const store = loadMetaStore();
    const config = store[`review_config_${account}`] || null;
    jsonResponse(res, 200, { config });
    return;
  }

  // ============ REVIEW CONFIG: save ============
  // POST /api/review/config — body: {account, placeId, cidHex}
  if (urlPath === '/api/review/config' && req.method === 'POST') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    let body;
    try { const raw = await readRequestBody(req, 64 * 1024); body = JSON.parse(raw.toString('utf8')); } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
    const { account, placeId, cidHex } = body || {};
    if (!account) { jsonResponse(res, 400, { error: 'MISSING_ACCOUNT' }); return; }
    if (!isKeyAllowed(account, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
    const { reviewUrl, cidDecimal } = buildReviewUrl(placeId, cidHex);
    const config = { account, placeId: placeId || null, cidHex: cidHex || null, cidDecimal, reviewUrl, updatedAt: new Date().toISOString() };
    const store = loadMetaStore();
    store[`review_config_${account}`] = config;
    saveMetaStore(store);
    jsonResponse(res, 200, { ok: true, config });
    return;
  }

  // ============ ACCOUNT-SCOPED DATA: get ============
  // GET /api/account-data?account=EMAIL&section=SECTION
  if (urlPath === '/api/account-data' && req.method === 'GET') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const { account, section } = qs;
    if (!account) { jsonResponse(res, 400, { error: 'MISSING_ACCOUNT' }); return; }
    if (!isKeyAllowed(account, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
    const data = loadAccountData(account);
    jsonResponse(res, 200, { data: section ? (data[section] || null) : data });
    return;
  }

  // ============ ACCOUNT-SCOPED DATA: save ============
  // PUT /api/account-data?account=EMAIL&section=SECTION
  if (urlPath === '/api/account-data' && req.method === 'PUT') {
    const rawToken = extractBearerToken(req);
    const payload = rawToken ? verifyMetaToken(rawToken) : null;
    if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const { account, section } = qs;
    if (!account) { jsonResponse(res, 400, { error: 'MISSING_ACCOUNT' }); return; }
    if (!isKeyAllowed(account, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
    let body;
    try { const raw = await readRequestBody(req, 2 * 1024 * 1024); body = JSON.parse(raw.toString('utf8')); } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
    const data = loadAccountData(account);
    if (section) {
      data[section] = body;
    } else {
      Object.assign(data, body);
    }
    saveAccountData(account, data);
    jsonResponse(res, 200, { ok: true });
    return;
  }

  if (urlPath === '/api/config' && req.method === 'GET') {
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

  if (urlPath === '/api/github/push' && req.method === 'POST') {
    await handleGithubPush(req, res);
    return;
  }
  if (urlPath === '/api/github/status' && req.method === 'GET') {
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

  const filePath = path.join(__dirname, 'index.html');
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) { res.writeHead(500); res.end('Error loading page'); return; }
    const patched = injectCalAdditions(html);
    const buf = Buffer.from(patched, 'utf8');
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Content-Length': buf.length
    });
    res.end(buf);
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
