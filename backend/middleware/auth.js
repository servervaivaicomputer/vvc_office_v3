const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const UAParser = require('ua-parser-js');
const { supabase } = require('../database/database');

const JWT_SECRET  = process.env.JWT_SECRET;
const COOKIE_NAME = process.env.JWT_COOKIE_NAME || '__Host-session';
const FRONTEND_URL = process.env.FRONTEND_URL;

/* ─── Helpers ─── */
const generateToken = (user) =>
  jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
  );

const getClientIP = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.headers['x-real-ip'] ||
  req.ip ||
  'unknown';

const parseDevice = (req) => {
  const p = new UAParser(req.headers['user-agent']);
  const b = p.getBrowser();
  const o = p.getOS();
  const d = p.getDevice();
  return {
    name: `${b.name || 'Unknown'} / ${o.name || 'Unknown'}${d.type ? ' (' + d.type + ')' : ''}`,
    ua: req.headers['user-agent'] || ''
  };
};

/* ─── Log Activity ─── */
const logActivity = async (data) => {
  try {
    await supabase.from('audit_logs').insert({
      user_id:    data.userId    || null,
      username:   data.username  || null,
      action:     data.action,
      page:       data.page      || null,
      ip:         data.ip        || null,
      device:     data.device    || null,
      user_agent: data.userAgent || null,
      status:     data.status    || 'success',
      details:    data.details   || null
    });
  } catch (e) {
    console.error('Audit log err:', e.message);
  }
};

/* ─── Record Device ─── */
const recordDevice = async (user, ip, dev) => {
  const { data: existing } = await supabase
    .from('devices')
    .select('id')
    .eq('user_id', user.id)
    .eq('ip', ip)
    .eq('name', dev.name)
    .single();

  if (existing) {
    await supabase
      .from('devices')
      .update({ last_seen: new Date().toISOString(), user_agent: dev.ua })
      .eq('id', existing.id);
  } else {
    await supabase.from('devices').insert({
      user_id:    user.id,
      name:       dev.name,
      ip:         ip,
      user_agent: dev.ua
    });
  }
};

/* ─── Auth Callback: ?auth=TOKEN → cookie ─── */
const handleAuthCallback = (req, res, next) => {
  const token = req.query.auth;
  if (!token) return next();

  try {
    jwt.verify(token, JWT_SECRET);
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure:   true,
      sameSite: 'None',
      path:     '/',
      maxAge:   8 * 60 * 60 * 1000
    });
    return res.redirect(302, `${FRONTEND_URL}/`);
  } catch {
    return res.redirect(302, `${FRONTEND_URL}/login/?error=invalid_token`);
  }
};

/* ─── Authenticate Every Request ─── */
const authenticate = async (req, res, next) => {
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

    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, role, page_access, is_blocked, failed_login_attempts, last_login, login_status')
      .eq('id', decoded.id)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account blocked' });
    }

    /* Check device block */
    const ip  = getClientIP(req);
    const dev = parseDevice(req);

    const { data: blockedDev } = await supabase
      .from('devices')
      .select('id')
      .eq('user_id', user.id)
      .eq('ip', ip)
      .eq('is_blocked', true)
      .single();

    if (blockedDev) {
      return res.status(403).json({ error: 'Device blocked' });
    }

    /* Normalize field names (snake_case → camelCase) */
    req.user = {
      id:          user.id,
      _id:         user.id,
      username:    user.username,
      role:        user.role,
      pageAccess:  user.page_access || [],
      isBlocked:   user.is_blocked,
      loginStatus: user.login_status,
      lastLogin:   user.last_login
    };
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

/* ─── Require Admin ─── */
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    return res.redirect(302, `${FRONTEND_URL}/login/?error=not_admin`);
  }
  next();
};

/* ─── Check Page Access ─── */
const checkPageAccess = (page) => (req, res, next) => {
  if (req.user.role === 'admin') return next();
  if (!req.user.pageAccess.includes(page)) {
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
