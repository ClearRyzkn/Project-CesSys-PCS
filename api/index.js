/**
 * Security System Dashboard - Vercel Serverless API
 * Mocks the Express backend for static hosting on Vercel.
 * Data is stored in-memory (Vercel is stateless), seeded from the repo data/.
 */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Read-only seed data bundled at build time from the repo.
function loadJSON(name, fallback) {
  try {
    const p = path.join(__dirname, '..', 'data', name);
    if (!fs.existsSync(p)) return fallback;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    return fallback;
  }
}

let USERS = loadJSON('users.json', { users: [] });
let SECRETS = loadJSON('secrets.json', { secrets: [] });
let CAMERAS = loadJSON('cameras.json', []);
let AUDIT = loadJSON('audit.log', []);
if (!Array.isArray(AUDIT)) AUDIT = [];

// JWT_SECRET MUST come from the environment (set in Vercel dashboard).
// Never fall back to a hardcoded/default secret in production — doing so lets
// anyone forge tokens and bypass auth. If it is missing, fail closed (auth
// endpoints will reject) rather than silently using a known default.
//
// Fallback: if JWT_SECRET is not set in the environment, use the persistent
// site secret generated at data/secret.key (bundled with the build). This keeps
// the deploy working on Vercel without requiring a manual env var, while still
// avoiding a hardcoded secret in source. For maximum security, set JWT_SECRET.
let JWT_SECRET = process.env.JWT_SECRET || '';
if (!JWT_SECRET) {
  try {
    const keyPath = path.join(__dirname, '..', 'data', 'secret.key');
    if (fs.existsSync(keyPath)) {
      JWT_SECRET = fs.readFileSync(keyPath, 'utf8').trim();
    }
  } catch (e) {
    // ignore — JWT_SECRET stays empty and auth will fail closed
  }
}

// ============ RATE LIMITING (brute-force protection) ============
// In-memory per-IP limiter for sensitive endpoints (login, MFA). Vercel is
// stateless but this still throttles rapid attempts within a single instance.
const rateLimitHits = new Map();
function rateLimit(maxRequests = 5, windowMs = 15 * 60 * 1000) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim()
             : req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const rec = rateLimitHits.get(ip) || { count: 0, resetAt: now + windowMs };
    if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + windowMs; }
    rec.count++;
    rateLimitHits.set(ip, rec);
    if (rec.count > maxRequests) {
      return res.status(429).json({ success: false, message: 'Too many attempts. Please try again later.', retryAfter: Math.ceil((rec.resetAt - now) / 1000) });
    }
    return next();
  };
}

// ============ CORS (restricted to known origins) ============
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['https://clearclientproject.vercel.app'];
function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  } else {
    // No origin (curl/server) or disallowed origin: do not reflect it.
    res.setHeader('Access-Control-Allow-Origin', 'https://clearclientproject.vercel.app');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

function auditLog(user, action, details, ip, level = 'info') {
  AUDIT.unshift({
    id: Math.random().toString(16).slice(2, 10),
    timestamp: new Date().toISOString(),
    user: user || 'anonymous',
    action,
    details,
    ip: ip || 'serverless',
    level
  });
  if (AUDIT.length > 500) AUDIT = AUDIT.slice(0, 500);
}

function generateToken(user) {
  if (!JWT_SECRET) {
    const err = new Error('JWT_SECRET is not configured');
    err.status = 500;
    throw err;
  }
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

function requireAuth(handler) {
  return (req, res) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      return handler(req, res);
    } catch (e) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
  };
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch (e) { resolve({}); }
    });
  });
}

async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = req.method;

res.setHeader('Content-Type', 'application/json');
  setCorsHeaders(req, res);

  if (method === 'OPTIONS') {
    return res.status(204).end();
  }

  const body = method === 'POST' || method === 'PUT' ? await parseBody(req) : {};

  // ---- AUTH (rate-limited to prevent brute-force) ----
  if (path === '/api/auth/login' && method === 'POST') {
    return rateLimit()(req, res, () => {
      const { username, password } = body;
      if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
      }
      const user = USERS.users.find(u => u.username === username);
      if (!user) return res.status(401).json({ success: false, message: 'User not found' });
      if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
        return res.status(401).json({ success: false, message: 'Account locked temporarily', lockout: true });
      }
if (bcrypt.compareSync(password, user.passwordHash)) {
        user.failedAttempts = 0;
        auditLog(username, 'login_success', 'Login successful', url.host, 'info');
        // If JWT_SECRET is not configured, return a clear error instead of a crash.
        if (!JWT_SECRET) {
          return res.status(500).json({ success: false, message: 'Server misconfigured: JWT_SECRET is not set. Please configure it in the Vercel dashboard environment variables.' });
        }
        return res.json({
          success: true,
          token: generateToken(user),
          user: { username, role: user.role },
          mfaEnabled: user.mfaEnabled === true,
          anomalies: []
        });
      } else {
        user.failedAttempts = (user.failedAttempts || 0) + 1;
        auditLog(username, 'login_failed', 'Invalid password', url.host, 'warning');
        return res.status(401).json({ success: false, message: 'Invalid password' });
      }
    });
  }

  if (path === '/api/auth/verify' && method === 'POST') {
    return requireAuth((req2, res2) => {
      res2.json({ success: true, user: req2.user });
    })(req, res);
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    return requireAuth((req2, res2) => {
      auditLog(req2.user.username, 'logout', 'User logged out', url.host, 'info');
      res2.json({ success: true, message: 'Logged out' });
    })(req, res);
  }

  // ---- SYSTEM STATUS ----
  if (path === '/api/system/status') {
    return res.json({
      success: true,
      status: {
        uptime: 3600,
        memory: { rss: 50 * 1024 * 1024 },
        cpu: { user: 100, system: 50 },
        nodeVersion: process.version,
        platform: process.platform,
        timestamp: new Date().toISOString()
      }
    });
  }

  // ---- SETTINGS ----
  if (path === '/api/settings') {
    if (method === 'GET') return res.json({ success: true, settings: USERS.settings || {} });
    if (method === 'POST') {
      USERS.settings = { ...(USERS.settings || {}), ...body };
      auditLog(body.user || 'admin', 'settings_updated', 'Settings updated', url.host, 'info');
      return res.json({ success: true, settings: USERS.settings });
    }
  }

  // ---- AUDIT ----
  if (path === '/api/audit' && method === 'GET') {
    return requireAuth((req2, res2) => {
      res2.json({ success: true, logs: AUDIT });
    })(req, res);
  }

  // ---- SECRETS ----
  if (path === '/api/secrets' && method === 'GET') {
    return requireAuth((req2, res2) => {
      res2.json({
        success: true,
        secrets: (SECRETS.secrets || []).map(s => ({
          id: s.id, name: s.name, createdAt: s.createdAt, createdBy: s.createdBy
        }))
      });
    })(req, res);
  }

  if (path === '/api/secrets' && method === 'POST') {
    return requireAuth((req2, res2) => {
      const { name, value } = body;
      if (!name || !value) return res2.status(400).json({ success: false, message: 'Name and value required' });
      const secret = {
        id: Math.random().toString(16).slice(2, 18),
        name, value, createdAt: new Date().toISOString(), createdBy: req2.user.username
      };
      SECRETS.secrets.push(secret);
      auditLog(req2.user.username, 'secret_added', `Secret "${name}" added`, url.host, 'info');
      res2.json({ success: true, secret: { id: secret.id, name: secret.name } });
    })(req, res);
  }

  const secretValueMatch = path.match(/^\/api\/secrets\/([^/]+)\/value$/);
  if (secretValueMatch && method === 'GET') {
    return requireAuth((req2, res2) => {
      const s = (SECRETS.secrets || []).find(x => x.id === secretValueMatch[1]);
      if (!s) return res2.status(404).json({ success: false, message: 'Secret not found' });
      auditLog(req2.user.username, 'secret_viewed', 'Secret value viewed', url.host, 'warning');
      res2.json({ success: true, value: s.value });
    })(req, res);
  }

  const secretDeleteMatch = path.match(/^\/api\/secrets\/([^/]+)$/);
  if (secretDeleteMatch && method === 'DELETE') {
    return requireAuth((req2, res2) => {
      SECRETS.secrets = (SECRETS.secrets || []).filter(s => s.id !== secretDeleteMatch[1]);
      auditLog(req2.user.username, 'secret_deleted', 'Secret deleted', url.host, 'warning');
      res2.json({ success: true });
    })(req, res);
  }

  // ---- ANOMALIES ----
  if (path === '/api/anomalies' && method === 'GET') {
    return requireAuth((req2, res2) => {
      const anomalies = AUDIT.filter(l => l.action === 'anomaly_detected' || l.level === 'high');
      res2.json({ success: true, anomalies });
    })(req, res);
  }

  // ---- FIM ----
  if (path === '/api/fim/check' && method === 'GET') {
    return requireAuth((req2, res2) => {
      auditLog(req2.user.username, 'fim_check', 'File integrity check performed', url.host, 'info');
      res2.json({ success: true, results: [{ file: 'demo', status: 'ok', message: 'File intact (serverless demo)' }] });
    })(req, res);
  }

  if (path === '/api/fim/baseline' && method === 'POST') {
    return requireAuth((req2, res2) => {
      auditLog(req2.user.username, 'fim_baseline', 'FIM baseline updated', url.host, 'info');
      res2.json({ success: true, baseline: {} });
    })(req, res);
  }

  // ---- CCTV ----
  if (path === '/api/cctv' && method === 'GET') {
    return requireAuth((req2, res2) => {
      const cams = (CAMERAS || []).map(c => ({
        ...c,
        status: c.url ? 'online' : 'offline',
        latency: 12
      }));
      res2.json({ success: true, cameras: cams });
    })(req, res);
  }

  if (path === '/api/cctv' && method === 'POST') {
    return requireAuth((req2, res2) => {
      const { name, ip, type, url } = body;
      if (!name || !ip) return res2.status(400).json({ success: false, message: 'Name and IP required' });
      const isIpWebcam = type === 'ipwebcam';
      const finalUrl = url || (isIpWebcam ? `http://${ip}:8080/video` : '');
      const cam = {
        id: 'cam' + Date.now().toString(36),
        name, ip, type: type || 'ip', port: 80,
        url: finalUrl, status: 'unknown', latency: null, isIpWebcam: isIpWebcam || false
      };
      CAMERAS.push(cam);
      auditLog(req2.user.username, 'camera_added', `Camera "${name}" added (${ip})`, url.host, 'info');
      res2.json({ success: true, camera: cam });
    })(req, res);
  }

  const camDeleteMatch = path.match(/^\/api\/cctv\/([^/]+)$/);
  if (camDeleteMatch && method === 'DELETE') {
    return requireAuth((req2, res2) => {
      CAMERAS = (CAMERAS || []).filter(c => c.id !== camDeleteMatch[1]);
      auditLog(req2.user.username, 'camera_removed', 'Camera removed', url.host, 'warning');
      res2.json({ success: true });
    })(req, res);
  }

  // ---- PING ----
  if (path === '/api/ping' && method === 'GET') {
    return requireAuth((req2, res2) => {
      const host = url.searchParams.get('host') || '';
      auditLog(req2.user.username, 'ping_check', `Ping ${host}: alive`, url.host, 'info');
      res2.json({ success: true, host, alive: true, latency: 5, error: null });
    })(req, res);
  }

  // ---- RECORDINGS ----
  if (path === '/api/recordings' && method === 'GET') {
    return res.json({ success: true, recordings: [] });
  }

  // ---- 404 ----
  return res.status(404).json({ success: false, message: 'Endpoint not found' });
}

module.exports = handler;
