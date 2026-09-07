const jwt        = require('jsonwebtoken');
const UAParser   = require('ua-parser-js');
const { User, AuditLog } = require('../database/database');

const JWT_SECRET     = process.env.JWT_SECRET;
const COOKIE_NAME    = process.env.JWT_COOKIE_NAME || '__Host-session';
const FRONTEND_URL   = process.env.FRONTEND_URL;

/* ─── Helpers ─── */
const generateToken = (user) =>
  jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h' });

const getClientIP = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.headers['x-real-ip'] || req.ip || 'unknown';

const parseDevice = (req) => {
  const p = new UAParser(req.headers['user-agent']);
  const b = p.getBrowser(), o = p.getOS(), d = p.getDevice();
  return {
    name: `${b.name || 'Unknown'} / ${o.name || 'Unknown'}${d.type ? ' (' + d.type + ')' : ''}`,
    ua: req.headers['user-agent'] || ''
  };
};

const logActivity = async (data) => {
  try { await AuditLog.create(data); } catch (e) { console.error('Audit log err:', e.message); }
};

const recordDevice = async (user, ip, dev) => {
  const existing = user.devices.find(d => d.ip === ip && d.name === dev.name);
  if (existing) {
    existing.lastSeen  = new Date();
    existing.userAgent = dev.ua;
  } else {
    user.devices.push({ name: dev.name, ip, userAgent: dev.ua });
  }
  await user.save();
};

/* ─── Middleware: consume one-time token from ?auth= query → cookie ─── */
const handleAuthCallback = (req, res, next) => {
  const token = req.query.auth;
  if (!token) return next();
  try {
    jwt.verify(token, JWT_SECRET);

    // Cookie সেট করো
    res.cookie(COOKIE_NAME, token, {
      httpOnly:  true,
      secure:   true,
      sameSite: 'None',
      path:     '/',
      maxAge:   8 * 60 * 60 * 1000
    });

    // ★ Backend URL-এ redirect না করে frontend URL-এ redirect করো
    return res.redirect(302, `${FRONTEND_URL}/about/`);
  } catch {
    return res.redirect(302, `${FRONTEND_URL}/login/?error=invalid_token`);
  }
};

/* ─── Middleware: authenticate every request ─── */
const authenticate = async (req, res, next) => {
  // Cookie বা Authorization header — যেকোনো একটা থেকে token নাও
  let token = req.cookies[COOKIE_NAME];

  if (!token) {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect(302, `${FRONTEND_URL}/login/?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.isBlocked) {
      return res.status(403).json({ error: 'Account blocked' });
    }

    /* Check if this device is blocked */
    const ip  = getClientIP(req);
    const dev = parseDevice(req);
    const blockedDev = user.devices.find(d => d.ip === ip && d.isBlocked);

    if (blockedDev) {
      return res.status(403).json({ error: 'Device blocked' });
    }

    req.user       = user;
    req.clientIP   = ip;
    req.deviceInfo = dev;
    next();

  } catch (e) {
    const reason = e.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: reason });
    }
    return res.redirect(302, `${FRONTEND_URL}/login/?error=${e.name === 'TokenExpiredError' ? 'expired' : 'invalid'}`);
  }
};

/* ─── Middleware: require admin role ─── */
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    return res.redirect(302, `${FRONTEND_URL}/login/?error=not_admin`);
  }
  next();
};

/* ─── Middleware: check per-page access ─── */
const checkPageAccess = (page) => (req, res, next) => {
  if (req.user.role === 'admin') return next();
  if (!req.user.pageAccess?.includes(page)) {
    return res.status(403).json({ error: 'Access denied', page });
  }
  next();
};

module.exports = {
  generateToken,
  getClientIP,
  parseDevice,
  handleAuthCallback,
  authenticate,
  requireAdmin,
  checkPageAccess,
  logActivity,
  recordDevice,
  COOKIE_NAME
};
