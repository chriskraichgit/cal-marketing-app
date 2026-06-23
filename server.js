const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');
const { URL } = require('url');

const PORT = 5000;
const HOST = '0.0.0.0';

const TOKEN_FILE = path.join(__dirname, '.gdrive-tokens.json');
const META_STORE_FILE = path.join(__dirname, '.cal-meta-store.json');
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

  if (urlPath === '/api/github/push' && req.method === 'POST') {
    await handleGithubPush(req, res);
    return;
  }
  if (urlPath === '/api/github/status' && req.method === 'GET') {
    await handleGithubStatus(req, res);
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
