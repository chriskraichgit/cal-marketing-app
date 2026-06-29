const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');
const { URL } = require('url');
const { createClient } = require('@supabase/supabase-js');
const ws = require('ws');
const { Pool } = require('pg');
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { realtime: { transport: ws } }
);
const pgPool = new Pool({ connectionString: process.env.DATABASE_URL });

const PORT = 5000;
const HOST = '0.0.0.0';

const TOKEN_FILE = path.join(__dirname, '.gdrive-tokens.json');
const GOOGLE_TOKEN_FILE = path.join(__dirname, '.google-tokens.json');
const META_STORE_FILE = path.join(__dirname, '.cal-meta-store.json');
const LOGO_DIR = path.join(__dirname, '.cal-logos');
try { if (!fs.existsSync(LOGO_DIR)) fs.mkdirSync(LOGO_DIR); } catch (e) {}
// Known users for server-side meta token issuance.
// Passwords are stored as SHA-256 hashes only — never plaintext.
// Agency/test roles may access any account key; admin/user roles may only access their own email key.
const SERVER_USERS = {
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
if (!process.env.CAL_META_SECRET) {
  console.warn('[CAL] WARNING: CAL_META_SECRET is not set.');
  console.warn('[CAL]   A random ephemeral secret was generated at startup.');
  console.warn('[CAL]   Every server restart will invalidate all existing meta tokens.');
  console.warn('[CAL]   Set CAL_META_SECRET as an environment secret for persistent sessions.');
}

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
  const existing = store[key] || {};
  const merged = Object.assign({}, existing);
  Object.keys(body).forEach(function(k) {
    if (k.indexOf('layoutPrefs_') === 0) {
      const exPrefs = existing[k] || {};
      const inPrefs = body[k] || {};
      const mergedPrefs = {};
      Object.keys(exPrefs).forEach(function(navKey) {
        const ev = exPrefs[navKey];
        mergedPrefs[navKey] = (ev !== null && typeof ev === 'object') ? ev : { v: !!ev, t: 0 };
      });
      Object.keys(inPrefs).forEach(function(navKey) {
        const iv = inPrefs[navKey];
        const normIv = (iv !== null && typeof iv === 'object') ? iv : { v: !!iv, t: 1 };
        const normEv = mergedPrefs[navKey] || { v: false, t: 0 };
        const it = normIv.t || 0;
        const et = normEv.t || 0;
        if (it >= et) mergedPrefs[navKey] = normIv;
      });
      merged[k] = mergedPrefs;
    } else {
      merged[k] = body[k];
    }
  });
  store[key] = merged;
  saveMetaStore(store);
  jsonResponse(res, 200, { ok: true });
}

function safeLogoFilename(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

async function handleLogoGet(req, res, qs) {
  const key = qs.key;
  if (!key) { jsonResponse(res, 400, { error: 'MISSING_KEY' }); return; }
  const base = safeLogoFilename(key);
  const dataFile = path.join(LOGO_DIR, base + '.data');
  const mimeFile = path.join(LOGO_DIR, base + '.mime');
  try {
    if (!fs.existsSync(dataFile)) { jsonResponse(res, 404, { error: 'NOT_FOUND' }); return; }
    const imgData = fs.readFileSync(dataFile);
    let mimeType = 'image/png';
    try { mimeType = fs.readFileSync(mimeFile, 'utf8').trim(); } catch (e) {}
    res.writeHead(200, { 'Content-Type': mimeType, 'Cache-Control': 'public, max-age=31536000' });
    res.end(imgData);
  } catch (e) { jsonResponse(res, 500, { error: 'READ_FAILED' }); }
}

async function handleLogoPut(req, res, qs) {
  const rawToken = extractBearerToken(req);
  const payload = rawToken ? verifyMetaToken(rawToken) : null;
  if (!payload) { jsonResponse(res, 401, { error: 'UNAUTHORIZED' }); return; }
  const key = qs.key;
  if (!key) { jsonResponse(res, 400, { error: 'MISSING_KEY' }); return; }
  if (!isKeyAllowed(key, payload)) { jsonResponse(res, 403, { error: 'FORBIDDEN' }); return; }
  let body;
  try {
    const raw = await readRequestBody(req, 5 * 1024 * 1024);
    body = JSON.parse(raw.toString('utf8'));
  } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BODY' }); return; }
  const dataUrl = body && typeof body.logo === 'string' ? body.logo : '';
  if (!dataUrl.startsWith('data:')) { jsonResponse(res, 400, { error: 'INVALID_LOGO' }); return; }
  const match = /^data:([^;]+);base64,(.+)$/.exec(dataUrl);
  if (!match) { jsonResponse(res, 400, { error: 'INVALID_DATA_URL' }); return; }
  const mimeType = match[1];
  let imgBuf;
  try { imgBuf = Buffer.from(match[2], 'base64'); } catch (e) { jsonResponse(res, 400, { error: 'INVALID_BASE64' }); return; }
  const base = safeLogoFilename(key);
  try {
    fs.writeFileSync(path.join(LOGO_DIR, base + '.data'), imgBuf);
    fs.writeFileSync(path.join(LOGO_DIR, base + '.mime'), mimeType);
  } catch (e) { jsonResponse(res, 500, { error: 'WRITE_FAILED' }); return; }
  const logoUrl = '/api/logo?key=' + encodeURIComponent(key);
  const store = loadMetaStore();
  store[key] = Object.assign({}, store[key] || {}, { logo: logoUrl });
  saveMetaStore(store);
  jsonResponse(res, 200, { ok: true, url: logoUrl });
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
    // After a boundary we expect either "--" (end) or "\r\n" then part data
    if (buffer[start] === 0x2d && buffer[start + 1] === 0x2d) break; // closing "--"
    if (buffer[start] === 0x0d && buffer[start + 1] === 0x0a) start += 2;
    const next = buffer.indexOf(boundaryBuf, start);
    if (next === -1) break;
    // Part is buffer[start .. next], strip trailing \r\n
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

// ── Supabase-backed Google token storage ──────────────────────────────────
async function loadGoogleTokens(companyId) {
  try {
    const { data, error } = await supabase
      .from('google_tokens')
      .select('tokens')
      .eq('company_id', companyId)
      .single();
    if (error || !data) return null;
    return data.tokens;
  } catch (e) {
    console.error('loadGoogleTokens error:', e.message);
    return null;
  }
}

async function saveGoogleTokens(companyId, tokens, userInfo) {
  try {
    const row = {
      company_id: companyId,
      tokens: tokens,
      updated_at: new Date().toISOString()
    };
    if (userInfo && userInfo.email) row.user_email = userInfo.email;
    if (userInfo && userInfo.name)  row.user_name  = userInfo.name;
    const { error } = await supabase
      .from('google_tokens')
      .upsert(row, { onConflict: 'company_id' });
    if (error) console.error('saveGoogleTokens error:', error.message);
  } catch (e) {
    console.error('saveGoogleTokens error:', e.message);
  }
}

async function deleteGoogleTokens(companyId) {
  try {
    const { error } = await supabase
      .from('google_tokens')
      .delete()
      .eq('company_id', companyId);
    if (error) console.error('deleteGoogleTokens error:', error.message);
  } catch (e) {
    console.error('deleteGoogleTokens error:', e.message);
  }
}

async function getGoogleAuthedClient(companyId) {
  const tokens = await loadGoogleTokens(companyId);
  if (!tokens) return null;
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
  oauth2Client.setCredentials(tokens);
  // Auto-refresh if expired
  if (tokens.expiry_date && tokens.expiry_date < Date.now() + 60000) {
    try {
      const { credentials } = await oauth2Client.refreshAccessToken();
      await saveGoogleTokens(companyId, credentials);
      oauth2Client.setCredentials(credentials);
    } catch (e) {
      console.error('Token refresh error for', companyId, e.message);
    }
  }
  return oauth2Client;
}
// ─────────────────────────────────────────────────────────────────────────────

async function handleGoogleConnect(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = createGoogleOAuth2Client();
  if (!oauth2) { jsonResponse(res, 200, { error: 'GOOGLE_CREDENTIALS_NOT_CONFIGURED', authUrl: null }); return; }
  const authUrl = oauth2.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    state: companyId,
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/business.manage',
      'https://www.googleapis.com/auth/webmasters.readonly',
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/analytics.readonly',
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/spreadsheets.readonly',
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
    const companyId = qs.state || 'default';
    const { tokens } = await oauth2.getToken(qs.code);
    let userInfo = {};
    try {
      oauth2.setCredentials(tokens);
      const oauth2api = google.oauth2({ version: 'v2', auth: oauth2 });
      const { data } = await oauth2api.userinfo.get();
      userInfo = { email: data.email, name: data.name };
    } catch(e) {}
    await saveGoogleTokens(companyId, tokens, userInfo);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html(null, false));
  } catch (e) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html(e.message, true)); }
}

async function handleGoogleStatus(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const tokens = await loadGoogleTokens(companyId);
  if (!tokens) {
    jsonResponse(res, 200, { connected: false, configured: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) });
    return;
  }
  const { data } = await supabase
    .from('google_tokens')
    .select('user_email, user_name')
    .eq('company_id', companyId)
    .single();
  jsonResponse(res, 200, {
    connected: true,
    configured: true,
    user: { email: data && data.user_email, name: data && data.user_name }
  });
}

async function handleGoogleDisconnect(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (oauth2) { try { const t = await loadGoogleTokens(companyId); const tok = t && (t.access_token || t.refresh_token); if (tok) await oauth2.revokeToken(tok); } catch (e) {} }
  await deleteGoogleTokens(companyId);
  jsonResponse(res, 200, { disconnected: true });
}

async function handleCompaniesStatus(res) {
  const companies = ['cal', 'apexlegal', 'unitedsewer', 'greencollar', 'willydiamond', 'housesautobody'];
  const statuses = {};
  for (const c of companies) {
    const tokens = await loadGoogleTokens(c);
    statuses[c] = { connected: !!tokens };
    if (tokens) {
      try {
        const oauth2 = await getGoogleAuthedClient(c);
        const api = google.oauth2({ version: 'v2', auth: oauth2 });
        const info = await api.userinfo.get();
        statuses[c].user = info.data.email;
      } catch (e) {
        statuses[c].connected = false;
        statuses[c].error = e.message;
      }
    }
  }
  jsonResponse(res, 200, { companies: statuses });
}

// ============ GOOGLE SIGN-IN (User Authentication) ============
// NOTE: Add this redirect URI to Google Cloud Console OAuth credentials:
// https://df44dd17-cdb7-4b8f-9e82-c52589af1601-00-1up1j4dm8544a.picard.replit.dev/api/auth/google/callback
function getSignInRedirectUri() {
  const domain = process.env.REPLIT_DEV_DOMAIN || process.env.REPLIT_DOMAINS || `localhost:${PORT}`;
  const host = domain.split(',')[0].trim();
  return `https://${host}/api/auth/google/callback`;
}

async function handleAuthGoogleStart(res) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><body><script>
      window.opener && window.opener.postMessage({ type: 'google-signin', success: false, error: 'Google credentials not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Replit Secrets.' }, '*');
      window.close();
    </script><p style="font-family:sans-serif;padding:20px">Google credentials not configured.</p></body></html>`);
    return;
  }
  const oauth2 = new google.auth.OAuth2(clientId, clientSecret, getSignInRedirectUri());
  const authUrl = oauth2.generateAuthUrl({
    access_type: 'online',
    prompt: 'select_account',
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
  });
  res.writeHead(302, { Location: authUrl });
  res.end();
}

async function handleAuthGoogleCallback(res, qs) {
  const fail = (msg) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><body><script>
      window.opener && window.opener.postMessage(${JSON.stringify({ type: 'google-signin', success: false, error: msg })}, '*');
      window.close();
    </script><p style="font-family:sans-serif;padding:20px">Sign-in failed: ${msg}</p></body></html>`);
  };
  if (qs.error) { fail(qs.error); return; }
  if (!qs.code) { fail('No authorization code received from Google.'); return; }
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) { fail('Google credentials not configured.'); return; }
  try {
    const oauth2 = new google.auth.OAuth2(clientId, clientSecret, getSignInRedirectUri());
    const { tokens } = await oauth2.getToken(qs.code);
    oauth2.setCredentials(tokens);
    const api = google.oauth2({ version: 'v2', auth: oauth2 });
    const info = await api.userinfo.get();
    const email = (info.data.email || '').toLowerCase();
    const name = info.data.name || '';
    const picture = info.data.picture || '';
    const payload = JSON.stringify({ type: 'google-signin', success: true, email, name, picture });
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><body><script>
      try { sessionStorage.setItem('google-signin-result', ${JSON.stringify(payload)}); } catch(e) {}
      window.opener && window.opener.postMessage(${payload}, '*');
      window.close();
    </script><p style="font-family:sans-serif;padding:20px">Signed in! You can close this window.</p></body></html>`);
  } catch (e) {
    fail(e.message);
  }
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
async function handleGBPAccounts(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', accounts: [] }); return; }
  try {
    const r = await googleApiGet(oauth2, 'https://mybusinessaccountmanagement.googleapis.com/v1/accounts');
    jsonResponse(res, 200, { accounts: r.body.accounts || [] });
  } catch (e) { jsonResponse(res, 200, { error: e.message, accounts: [] }); }
}

async function handleGBPLocations(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', locations: [] }); return; }
  let account = qs.account;
  try {
    if (!account) {
      const accountsRes = await googleApiGet(oauth2, 'https://mybusinessaccountmanagement.googleapis.com/v1/accounts');
      const accounts = accountsRes.body.accounts || [];
      if (!accounts.length) { jsonResponse(res, 200, { error: 'NO_GBP_ACCOUNTS', locations: [] }); return; }
      account = accounts[0].name;
    }
    const r = await googleApiGet(oauth2, `https://mybusinessbusinessinformation.googleapis.com/v1/${account}/locations?readMask=name,title,storefrontAddress,websiteUri`);
    jsonResponse(res, 200, { locations: r.body.locations || [] });
  } catch (e) { jsonResponse(res, 200, { error: e.message, locations: [] }); }
}

async function handleGBPReviews(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', reviews: [] }); return; }
  let location = qs.location;
  try {
    if (!location) {
      const accountsRes = await googleApiGet(oauth2, 'https://mybusinessaccountmanagement.googleapis.com/v1/accounts');
      const accounts = accountsRes.body.accounts || [];
      if (!accounts.length) { jsonResponse(res, 200, { error: 'NO_GBP_ACCOUNTS', reviews: [] }); return; }
      const locRes = await googleApiGet(oauth2, `https://mybusinessbusinessinformation.googleapis.com/v1/${accounts[0].name}/locations?readMask=name,title,storefrontAddress,websiteUri`);
      const locations = locRes.body.locations || [];
      if (!locations.length) { jsonResponse(res, 200, { error: 'NO_GBP_LOCATIONS', reviews: [] }); return; }
      location = locations[0].name;
    }
    const r = await googleApiGet(oauth2, `https://mybusiness.googleapis.com/v4/${location}/reviews`);
    jsonResponse(res, 200, { reviews: r.body.reviews || [], averageRating: r.body.averageRating || null });
  } catch (e) { jsonResponse(res, 200, { error: e.message, reviews: [] }); }
}

async function handleGBPInsights(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  let locationName = qs && qs.location;
  res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  try {
    const auth = await getGoogleAuthedClient(companyId);
    if (!auth) { res.end(JSON.stringify({ error: 'not_connected' })); return; }
    if (!locationName) {
      const accountsRes = await googleApiGet(auth, 'https://mybusinessaccountmanagement.googleapis.com/v1/accounts');
      const accounts = accountsRes.body.accounts || [];
      if (!accounts.length) { res.end(JSON.stringify({ error: 'no_gbp_accounts' })); return; }
      const locRes = await googleApiGet(auth, `https://mybusinessbusinessinformation.googleapis.com/v1/${accounts[0].name}/locations?readMask=name,title,storefrontAddress,websiteUri`);
      const locations = locRes.body.locations || [];
      if (!locations.length) { res.end(JSON.stringify({ error: 'no_location' })); return; }
      const locRaw = locations[0].name || '';
      const m = locRaw.match(/locations\/\d+/);
      locationName = m ? m[0] : locRaw;
    }
    const tokenInfo = await auth.getAccessToken();
    const accessToken = tokenInfo && tokenInfo.token;
    if (!accessToken) { res.end(JSON.stringify({ error: 'not_connected' })); return; }
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - 30);
    const body = JSON.stringify({
      dailyRange: {
        startDate: { year: startDate.getFullYear(), month: startDate.getMonth() + 1, day: startDate.getDate() },
        endDate:   { year: endDate.getFullYear(),   month: endDate.getMonth() + 1,   day: endDate.getDate() }
      },
      multiDailyMetricTimeSeries: [
        { dailyMetric: 'CALL_CLICKS' },
        { dailyMetric: 'WEBSITE_CLICKS' },
        { dailyMetric: 'DIRECTION_REQUESTS' },
        { dailyMetric: 'BUSINESS_IMPRESSIONS_MOBILE_SEARCH' },
        { dailyMetric: 'BUSINESS_IMPRESSIONS_DESKTOP_SEARCH' },
        { dailyMetric: 'BUSINESS_IMPRESSIONS_MOBILE_MAPS' },
        { dailyMetric: 'BUSINESS_IMPRESSIONS_DESKTOP_MAPS' }
      ]
    });
    const https = require('https');
    const urlMod = require('url');
    const apiUrl = 'https://businessprofileperformance.googleapis.com/v1/' + locationName + ':fetchMultiDailyMetricTimeSeries';
    const parsed = urlMod.parse(apiUrl);
    const data = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: parsed.hostname,
        path: parsed.path,
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + accessToken,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body)
        }
      }, (resp) => {
        let raw = '';
        resp.on('data', chunk => raw += chunk);
        resp.on('end', () => { try { resolve(JSON.parse(raw)); } catch(e) { resolve({ raw }); } });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    const totals = {};
    if (data.multiDailyMetricTimeSeries) {
      data.multiDailyMetricTimeSeries.forEach(item => {
        let total = 0;
        if (item.timeSeries && item.timeSeries.datedValues) {
          item.timeSeries.datedValues.forEach(dv => { total += parseInt(dv.value || 0); });
        }
        totals[item.dailyMetric] = total;
      });
    }
    const totalImpressions = (totals['BUSINESS_IMPRESSIONS_MOBILE_SEARCH'] || 0)
      + (totals['BUSINESS_IMPRESSIONS_DESKTOP_SEARCH'] || 0)
      + (totals['BUSINESS_IMPRESSIONS_MOBILE_MAPS'] || 0)
      + (totals['BUSINESS_IMPRESSIONS_DESKTOP_MAPS'] || 0);
    res.end(JSON.stringify({
      calls: totals['CALL_CLICKS'] || 0,
      websiteClicks: totals['WEBSITE_CLICKS'] || 0,
      directionRequests: totals['DIRECTION_REQUESTS'] || 0,
      impressions: totalImpressions,
      raw: data
    }));
  } catch(e) {
    res.end(JSON.stringify({ error: e.message }));
  }
}

async function handleGBPReply(req, res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
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
async function handleGSCSites(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', sites: [] }); return; }
  try {
    const sc = google.searchconsole({ version: 'v1', auth: oauth2 });
    const r = await sc.sites.list();
    jsonResponse(res, 200, { sites: r.data.siteEntry || [] });
  } catch (e) { jsonResponse(res, 200, { error: e.message, sites: [] }); }
}

async function handleGSCAnalytics(req, res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
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
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
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

// ---- GA4 ----
async function handleGA4Properties(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', properties: [] }); return; }
  try {
    const admin = google.analyticsadmin({ version: 'v1beta', auth: oauth2 });
    const r = await admin.properties.list({ filter: 'parent:accounts/-' });
    const properties = (r.data.properties || []).map(p => ({
      id: p.name.replace('properties/', ''),
      name: p.displayName,
      timezone: p.timeZone,
      currency: p.currencyCode,
    }));
    jsonResponse(res, 200, { properties });
  } catch (e) { jsonResponse(res, 200, { error: e.message, properties: [] }); }
}

async function handleGA4Report(req, res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', rows: [] }); return; }
  const propertyId = qs.propertyId;
  if (!propertyId) { jsonResponse(res, 400, { error: 'MISSING_PROPERTY_ID' }); return; }
  let body = {};
  if (req.method === 'POST') {
    try { const raw = await readRequestBody(req, 32 * 1024); body = JSON.parse(raw.toString('utf8')); } catch (e) {}
  }
  try {
    const data = google.analyticsdata({ version: 'v1beta', auth: oauth2 });
    const r = await data.properties.runReport({
      property: `properties/${propertyId}`,
      requestBody: {
        dateRanges: body.dateRanges || [{ startDate: '28daysAgo', endDate: 'today' }],
        metrics: body.metrics || [
          { name: 'sessions' },
          { name: 'activeUsers' },
          { name: 'newUsers' },
          { name: 'bounceRate' },
          { name: 'averageSessionDuration' },
          { name: 'conversions' },
        ],
        dimensions: body.dimensions || [{ name: 'date' }],
        orderBys: body.orderBys || [{ dimension: { dimensionName: 'date' } }],
        limit: body.limit || 30,
      },
    });
    jsonResponse(res, 200, {
      rows: r.data.rows || [],
      totals: r.data.totals || [],
      rowCount: r.data.rowCount || 0,
      dimensionHeaders: r.data.dimensionHeaders || [],
      metricHeaders: r.data.metricHeaders || [],
    });
  } catch (e) { jsonResponse(res, 200, { error: e.message, rows: [] }); }
}

// ---- Gmail ----
async function handleGmailMessages(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', messages: [] }); return; }
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2 });
    const listRes = await gmail.users.messages.list({
      userId: 'me',
      q: qs.q || '',
      maxResults: parseInt(qs.maxResults) || 20,
      pageToken: qs.pageToken || undefined,
    });
    const messageIds = (listRes.data.messages || []);
    const messages = await Promise.all(
      messageIds.map(async (m) => {
        const msg = await gmail.users.messages.get({ userId: 'me', id: m.id, format: 'metadata', metadataHeaders: ['From', 'To', 'Subject', 'Date'] });
        const headers = {};
        (msg.data.payload.headers || []).forEach(h => { headers[h.name.toLowerCase()] = h.value; });
        return {
          id: m.id,
          threadId: m.threadId,
          snippet: msg.data.snippet,
          subject: headers['subject'] || '(no subject)',
          from: headers['from'] || '',
          to: headers['to'] || '',
          date: headers['date'] || '',
          labelIds: msg.data.labelIds || [],
        };
      })
    );
    jsonResponse(res, 200, { messages, nextPageToken: listRes.data.nextPageToken || null, resultSizeEstimate: listRes.data.resultSizeEstimate || 0 });
  } catch (e) { jsonResponse(res, 200, { error: e.message, messages: [] }); }
}

// ---- Google Sheets ----
async function handleSheetsRead(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED', values: [] }); return; }
  const spreadsheetId = qs.spreadsheetId;
  if (!spreadsheetId) { jsonResponse(res, 400, { error: 'MISSING_SPREADSHEET_ID' }); return; }
  try {
    const sheets = google.sheets({ version: 'v4', auth: oauth2 });
    const range = qs.range || 'Sheet1';
    const r = await sheets.spreadsheets.values.get({ spreadsheetId, range });
    jsonResponse(res, 200, { values: r.data.values || [], range: r.data.range, majorDimension: r.data.majorDimension });
  } catch (e) { jsonResponse(res, 200, { error: e.message, values: [] }); }
}

async function handleSheetsMetadata(res, qs) {
  const companyId = (qs && qs.company) || 'default';
  const oauth2 = await getGoogleAuthedClient(companyId);
  if (!oauth2) { jsonResponse(res, 200, { error: 'NOT_CONNECTED' }); return; }
  const spreadsheetId = qs.spreadsheetId;
  if (!spreadsheetId) { jsonResponse(res, 400, { error: 'MISSING_SPREADSHEET_ID' }); return; }
  try {
    const sheets = google.sheets({ version: 'v4', auth: oauth2 });
    const r = await sheets.spreadsheets.get({ spreadsheetId, includeGridData: false });
    jsonResponse(res, 200, {
      title: r.data.properties.title,
      sheets: (r.data.sheets || []).map(s => ({ title: s.properties.title, sheetId: s.properties.sheetId, rowCount: s.properties.gridProperties.rowCount, columnCount: s.properties.gridProperties.columnCount })),
    });
  } catch (e) { jsonResponse(res, 200, { error: e.message }); }
}

// ---- PageSpeed Insights ----
async function handlePageSpeed(res, qs) {
  const url = qs.url;
  if (!url) { jsonResponse(res, 400, { error: 'MISSING_URL' }); return; }
  const strategy = qs.strategy || 'mobile';
  const apiKey = process.env.GOOGLE_API_KEY || process.env.PAGESPEED_API_KEY || '';
  try {
    const apiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=${strategy}&category=performance&category=accessibility&category=best-practices&category=seo${apiKey ? '&key=' + apiKey : ''}`;
    const r = await fetch(apiUrl);
    const data = await r.json();
    if (data.error) { jsonResponse(res, 200, { error: data.error.message }); return; }
    const cats = data.lighthouseResult.categories;
    const audits = data.lighthouseResult.audits;
    jsonResponse(res, 200, {
      url,
      strategy,
      scores: {
        performance: Math.round((cats.performance?.score || 0) * 100),
        accessibility: Math.round((cats.accessibility?.score || 0) * 100),
        bestPractices: Math.round((cats['best-practices']?.score || 0) * 100),
        seo: Math.round((cats.seo?.score || 0) * 100),
      },
      metrics: {
        fcp: audits['first-contentful-paint']?.displayValue,
        lcp: audits['largest-contentful-paint']?.displayValue,
        tbt: audits['total-blocking-time']?.displayValue,
        cls: audits['cumulative-layout-shift']?.displayValue,
        si: audits['speed-index']?.displayValue,
        tti: audits['interactive']?.displayValue,
      },
      opportunities: Object.values(audits)
        .filter(a => a.details?.type === 'opportunity' && a.score !== null && a.score < 0.9)
        .map(a => ({ id: a.id, title: a.title, description: a.description, score: a.score, displayValue: a.displayValue }))
        .slice(0, 10),
    });
  } catch (e) { jsonResponse(res, 200, { error: e.message }); }
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

// Read from local file cache (synchronous, fast)
function loadStripeConnectFile() {
  try { if (fs.existsSync(STRIPE_TOKEN_FILE)) return JSON.parse(fs.readFileSync(STRIPE_TOKEN_FILE, 'utf8')); } catch (e) {}
  return null;
}

// Read from Replit PostgreSQL (durable, survives filesystem wipes)
async function loadStripeConnectDb() {
  try {
    const res = await pgPool.query('SELECT account_id, email, country, connected_at FROM stripe_connection WHERE id = 1');
    if (res.rows.length > 0) {
      const row = res.rows[0];
      return { accountId: row.account_id, email: row.email, country: row.country, connectedAt: row.connected_at };
    }
  } catch (e) {}
  return null;
}

// Write to both file cache and Replit PostgreSQL
async function saveStripeConnect(data) {
  try { fs.writeFileSync(STRIPE_TOKEN_FILE, JSON.stringify(data, null, 2)); } catch (e) {}
  try {
    await pgPool.query(
      `INSERT INTO stripe_connection (id, account_id, email, country, connected_at)
       VALUES (1, $1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET account_id=$1, email=$2, country=$3, connected_at=$4`,
      [data.accountId, data.email || null, data.country || null, data.connectedAt || Date.now()]
    );
  } catch (e) { console.error('[Stripe] Failed to persist to database:', e.message); }
}

// Remove from both file cache and Replit PostgreSQL
async function deleteStripeConnect() {
  try { if (fs.existsSync(STRIPE_TOKEN_FILE)) fs.unlinkSync(STRIPE_TOKEN_FILE); } catch (e) {}
  try { await pgPool.query('DELETE FROM stripe_connection WHERE id = 1'); } catch (e) {}
}

// Auto-seed Stripe config on startup: file cache → PostgreSQL → Stripe API
if (process.env.STRIPE_SECRET_KEY) {
  (async () => {
    // Ensure the table exists (idempotent)
    try {
      await pgPool.query(`CREATE TABLE IF NOT EXISTS stripe_connection (
        id INTEGER PRIMARY KEY DEFAULT 1,
        account_id TEXT NOT NULL,
        email TEXT,
        country TEXT,
        connected_at BIGINT,
        CONSTRAINT single_row CHECK (id = 1)
      )`);
    } catch (e) { console.error('[Stripe] Failed to ensure table:', e.message); }

    const fileData = loadStripeConnectFile();
    if (fileData) {
      // File cache hit — sync to DB in background if missing there
      const dbData = await loadStripeConnectDb();
      if (!dbData) {
        try {
          await pgPool.query(
            `INSERT INTO stripe_connection (id, account_id, email, country, connected_at)
             VALUES (1, $1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET account_id=$1, email=$2, country=$3, connected_at=$4`,
            [fileData.accountId, fileData.email || null, fileData.country || null, fileData.connectedAt || Date.now()]
          );
          console.log('[Stripe] Synced existing config to database for account', fileData.accountId);
        } catch (e) { console.error('[Stripe] Failed to sync to database:', e.message); }
      }
      return;
    }
    const fromDb = await loadStripeConnectDb();
    if (fromDb) {
      // Restore the local file cache from DB — no Stripe API call needed
      try { fs.writeFileSync(STRIPE_TOKEN_FILE, JSON.stringify(fromDb, null, 2)); } catch (e) {}
      console.log('[Stripe] Restored config from database for account', fromDb.accountId);
      return;
    }
    // Neither file nor DB — hit the Stripe API as a last resort
    try {
      const r = await stripeApiRequest('GET', '/v1/account', null);
      if (r.status === 200 && r.body && r.body.id) {
        await saveStripeConnect({ accountId: r.body.id, email: r.body.email, country: r.body.country, connectedAt: Date.now() });
        console.log('[Stripe] Auto-seeded config for account', r.body.id);
      } else {
        console.warn('[Stripe] Auto-seed: unexpected response status', r.status);
      }
    } catch (e) {
      console.error('[Stripe] Auto-seed failed:', e.message);
    }
  })();
}

async function handleStripeConnect(req, res) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) { jsonResponse(res, 200, { ok: false, error: 'STRIPE_SECRET_KEY not set' }); return; }
  try {
    const r = await stripeApiRequest('GET', '/v1/account', null);
    if (r.status === 200 && r.body.id) {
      await saveStripeConnect({ accountId: r.body.id, email: r.body.email, country: r.body.country, connectedAt: Date.now() });
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
      // Auto-save so future startups find data in Supabase and skip the API call
      if (!loadStripeConnectFile()) {
        await saveStripeConnect({ accountId: r.body.id, email: r.body.email, country: r.body.country, connectedAt: Date.now() });
      }
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
  await deleteStripeConnect();
  jsonResponse(res, 200, { disconnected: true });
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
  if (urlPath === '/api/logo' && req.method === 'GET') {
    await handleLogoGet(req, res, qs);
    return;
  }
  if (urlPath === '/api/logo' && req.method === 'POST') {
    await handleLogoPut(req, res, qs);
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

  if (urlPath === '/api/auth/google/start' && req.method === 'GET') { await handleAuthGoogleStart(res); return; }
  if (urlPath === '/api/auth/google/callback' && req.method === 'GET') { await handleAuthGoogleCallback(res, qs); return; }
  if (urlPath === '/api/google/connect' && req.method === 'GET') { await handleGoogleConnect(res, qs); return; }
  if (urlPath === '/api/google/callback' && req.method === 'GET') { await handleGoogleCallback(res, qs); return; }
  if (urlPath === '/api/google/status' && req.method === 'GET') { await handleGoogleStatus(res, qs); return; }
  if (urlPath === '/api/google/disconnect' && req.method === 'POST') { await handleGoogleDisconnect(res, qs); return; }
  if (urlPath === '/api/companies/status' && req.method === 'GET') { await handleCompaniesStatus(res); return; }
  if (urlPath === '/api/gbp/accounts' && req.method === 'GET') { await handleGBPAccounts(res, qs); return; }
  if (urlPath === '/api/gbp/locations' && req.method === 'GET') { await handleGBPLocations(res, qs); return; }
  if (urlPath === '/api/gbp/reviews' && req.method === 'GET') { await handleGBPReviews(res, qs); return; }
  if (urlPath === '/api/gbp/insights' && req.method === 'GET') { await handleGBPInsights(res, qs); return; }
  if (urlPath === '/api/gbp/reply' && req.method === 'POST') { await handleGBPReply(req, res, qs); return; }
  if (urlPath === '/api/gsc/sites' && req.method === 'GET') { await handleGSCSites(res, qs); return; }
  if (urlPath === '/api/gsc/analytics') { await handleGSCAnalytics(req, res, qs); return; }
  if (urlPath === '/api/gsc/performance') { await handleGSCAnalytics(req, res, qs); return; }
  if (urlPath === '/api/ga4/properties' && req.method === 'GET') { await handleGA4Properties(res, qs); return; }
  if (urlPath === '/api/ga4/report') { await handleGA4Report(req, res, qs); return; }
  if (urlPath === '/api/gmail/messages' && req.method === 'GET') { await handleGmailMessages(res, qs); return; }
  if (urlPath === '/api/sheets/read' && req.method === 'GET') { await handleSheetsRead(res, qs); return; }
  if (urlPath === '/api/sheets/metadata' && req.method === 'GET') { await handleSheetsMetadata(res, qs); return; }
  if (urlPath === '/api/pagespeed' && req.method === 'GET') { await handlePageSpeed(res, qs); return; }
  if (urlPath === '/api/calendar/events' && req.method === 'GET') { await handleCalendarEvents(res, qs); return; }
  if (urlPath === '/api/stripe/connect' && req.method === 'POST') { await handleStripeConnect(req, res); return; }
  if (urlPath === '/api/stripe/status' && req.method === 'GET') { await handleStripeStatus(res); return; }
  if (urlPath === '/api/stripe/revenue' && req.method === 'GET') { await handleStripeRevenue(res, qs); return; }
  if (urlPath === '/api/stripe/disconnect' && req.method === 'POST') { await handleStripeDisconnect(res); return; }

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

    // Files to push via GitHub API
    const filesToPush = ['index.html', 'full-code.html', 'server.js'];
    const now = new Date().toISOString().replace('T', ' ').slice(0, 16);
    const commitMessage = 'CAL OS update — ' + now + ' UTC';
    const errors = [];

    for (const filename of filesToPush) {
      const filePath = path.join(__dirname, filename);
      if (!fs.existsSync(filePath)) continue;
      const content = fs.readFileSync(filePath);
      const b64 = content.toString('base64');

      // Get current SHA of file (needed for update)
      const existing = await githubApiRequest('GET', '/repos/' + owner + '/' + repo + '/contents/' + filename + '?ref=' + branch, pat, null);
      const sha = existing.status === 200 ? existing.body.sha : undefined;

      // Push file
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
