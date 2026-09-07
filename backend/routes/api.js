const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const { supabase } = require('../database/database');
const {
  generateToken,
  getClientIP,
  parseDevice,
  authenticate,
  requireAdmin,
  logActivity,
  recordDevice,
  COOKIE_NAME
} = require('../middleware/auth');

const router = express.Router();

const LOGIN_MAX = Number.parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10) || 10;
const REQUEST_MAX = Number.parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100;
const MAX_FAILED_ATTEMPTS = Number.parseInt(process.env.MAX_FAILED_ATTEMPTS, 10) || 10;
const FRONTEND_URL = process.env.FRONTEND_URL || '';
const ALLOWED_PAGES = ['home', 'about', 'workspace', 'landing'];
const ALLOWED_ROLES = ['user', 'admin'];

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: LOGIN_MAX,
  message: { error: 'Too many login attempts' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: REQUEST_MAX,
  standardHeaders: true,
  legacyHeaders: false
});

router.use(apiLimiter);

function normalizeUsername(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, function (character) {
    const entities = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    };
    return entities[character];
  });
}

function validUsername(username) {
  return username.length >= 1 && username.length <= 100 && !/[\u0000-\u001f\u007f]/.test(username);
}

function normalizePageAccess(value) {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(value.filter(function (page) {
    return typeof page === 'string' && ALLOWED_PAGES.includes(page);
  })));
}

function normalizeRole(value) {
  return ALLOWED_ROLES.includes(value) ? value : 'user';
}

function requestToken(req) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() : '';
}

function replacePageTokens(html, userPages, username, role, extraTokens) {
  const tokens = Object.assign({
    USERNAME: escapeHtml(username),
    ROLE: escapeHtml(role),
    USER_PAGES: JSON.stringify(userPages),
    FRONTEND_URL: escapeHtml(FRONTEND_URL)
  }, extraTokens || {});

  return html.replace(/\{\{([A-Z_]+)\}\}/g, function (_match, token) {
    return Object.prototype.hasOwnProperty.call(tokens, token) ? tokens[token] : '';
  });
}

function todayStart() {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
}

function dateDaysAgo(days) {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function supabaseError(result, fallback) {
  return result && result.error ? result.error.message || fallback : null;
}

async function findUserById(id) {
  return supabase.from('users')
    .select('id, username, role, page_access, is_blocked, blocked_by, blocked_at, blocked_reason, failed_login_attempts, last_failed_attempt, last_login, last_login_ip, last_login_device, login_status, created_at, updated_at')
    .eq('id', id)
    .single();
}

async function authenticateCredentials(username, password, req, res, options) {
  const userResult = await supabase.from('users').select('*').eq('username', username).single();
  const user = userResult.data;
  const adminOnly = options && options.adminOnly;
  const invalidMessage = adminOnly ? 'Invalid admin credentials.' : 'Invalid credentials.';

  if (userResult.error || !user || (adminOnly && user.role !== 'admin')) {
    return res.status(401).json({ error: invalidMessage });
  }
  if (user.is_blocked) {
    await logActivity({
      userId: user.id,
      username: user.username,
      action: 'login_failed',
      ip: getClientIP(req),
      device: parseDevice(req).name,
      userAgent: parseDevice(req).ua,
      status: 'blocked',
      details: 'Blocked account'
    });
    return res.status(403).json({ error: adminOnly ? 'Admin account blocked.' : 'Account blocked. Contact admin.' });
  }

  const ip = getClientIP(req);
  const device = parseDevice(req);
  const blockedDevice = await supabase.from('devices').select('id')
    .eq('user_id', user.id)
    .eq('ip', ip)
    .eq('is_blocked', true)
    .maybeSingle();
  if (blockedDevice.data) {
    await logActivity({ userId: user.id, username: user.username, action: 'login_failed', ip, device: device.name, userAgent: device.ua, status: 'blocked', details: 'Blocked device' });
    return res.status(403).json({ error: 'This device is blocked.' });
  }

  const passwordMatches = await bcrypt.compare(password, user.password || '');
  if (!passwordMatches) {
    const attempts = (Number(user.failed_login_attempts) || 0) + 1;
    const update = {
      failed_login_attempts: attempts,
      last_failed_attempt: new Date().toISOString()
    };
    if (attempts >= MAX_FAILED_ATTEMPTS) {
      update.is_blocked = true;
      update.blocked_by = 'auto';
      update.blocked_at = new Date().toISOString();
      update.blocked_reason = 'Auto-blocked after ' + MAX_FAILED_ATTEMPTS + ' failed attempts';
      update.login_status = 'blocked';
    }
    await supabase.from('users').update(update).eq('id', user.id);
    await logActivity({
      userId: user.id,
      username: user.username,
      action: attempts >= MAX_FAILED_ATTEMPTS ? 'blocked' : 'login_failed',
      ip,
      device: device.name,
      userAgent: device.ua,
      status: 'failure',
      details: 'Attempt ' + attempts + '/' + MAX_FAILED_ATTEMPTS
    });
    return res.status(401).json({
      error: invalidMessage,
      attemptsRemaining: Math.max(0, MAX_FAILED_ATTEMPTS - attempts)
    });
  }

  const pageAccess = normalizePageAccess(user.page_access);
  const normalizedUser = { id: user.id, username: user.username, role: user.role, pageAccess };
  const now = new Date().toISOString();
  const updateResult = await supabase.from('users').update({
    failed_login_attempts: 0,
    last_login: now,
    last_login_ip: ip,
    last_login_device: device.name,
    login_status: 'active'
  }).eq('id', user.id);
  if (updateResult.error) console.error('Login update error:', updateResult.error.message);

  await recordDevice(normalizedUser, ip, device);
  const token = generateToken(normalizedUser);
  await logActivity({ userId: user.id, username: user.username, action: 'login', ip, device: device.name, userAgent: device.ua, status: 'success', details: adminOnly ? 'Admin login OK' : 'Login OK' });
  return res.json({
    success: true,
    token,
    user: {
      username: user.username,
      role: user.role,
      pageAccess: adminOnly ? undefined : pageAccess
    }
  });
}

// Authentication
router.post('/auth/login', loginLimiter, async function (req, res) {
  try {
    const username = normalizeUsername(req.body && req.body.username);
    const password = req.body && req.body.password;
    if (!validUsername(username) || typeof password !== 'string' || password.length === 0) {
      return res.status(400).json({ error: 'Username and password required.' });
    }
    return await authenticateCredentials(username, password, req, res, { adminOnly: false });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error.' });
  }
});

router.post('/auth/admin-login', loginLimiter, async function (req, res) {
  try {
    const username = normalizeUsername(req.body && req.body.username);
    const password = req.body && req.body.password;
    if (!validUsername(username) || typeof password !== 'string' || password.length === 0) {
      return res.status(400).json({ error: 'Credentials required.' });
    }
    return await authenticateCredentials(username, password, req, res, { adminOnly: true });
  } catch (error) {
    console.error('Admin login error:', error);
    return res.status(500).json({ error: 'Server error.' });
  }
});

router.post('/auth/logout', authenticate, async function (req, res) {
  try {
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'logout', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
    res.clearCookie(COOKIE_NAME, { path: '/' });
    return res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ error: 'Server error.' });
  }
});

router.get('/auth/me', authenticate, function (req, res) {
  return res.json({
    user: {
      id: req.user._id,
      username: req.user.username,
      role: req.user.role,
      pageAccess: req.user.pageAccess,
      lastLogin: req.user.lastLogin,
      loginStatus: req.user.loginStatus
    }
  });
});

// Protected page content
router.get('/pages/:pageName', authenticate, async function (req, res) {
  try {
    const page = req.params.pageName;
    if (!ALLOWED_PAGES.includes(page)) return res.status(404).json({ error: 'Page not found' });
    if (req.user.role !== 'admin' && !req.user.pageAccess.includes(page)) {
      return res.status(403).json({ error: 'Access denied', page });
    }

    const filePath = path.join(__dirname, '..', 'projects', page, 'index.html');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Page file not found' });
    const html = replacePageTokens(fs.readFileSync(filePath, 'utf8'), req.user.pageAccess, req.user.username, req.user.role);
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'page_view', page, ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
    res.type('html').send(html);
  } catch (error) {
    console.error('Page serve error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin panel HTML
router.get('/admin/panel-content', authenticate, requireAdmin, async function (req, res) {
  try {
    const filePath = path.join(__dirname, '..', 'admin', 'index.html');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Admin panel not found' });
    const backendUrl = req.protocol + '://' + req.get('host');
    const html = replacePageTokens(
      fs.readFileSync(filePath, 'utf8'),
      req.user.pageAccess,
      req.user.username,
      req.user.role,
      { BACKEND_URL: escapeHtml(backendUrl), AUTH_TOKEN: escapeHtml(requestToken(req)) }
    );
    res.type('html').send(html);
  } catch (error) {
    console.error('Admin panel error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin dashboard
router.get('/admin/dashboard', authenticate, requireAdmin, async function (_req, res) {
  try {
    const today = todayStart();
    const d7 = dateDaysAgo(7);
    const d30 = dateDaysAgo(30);
    const [total, blocked, todayLogins, viewsToday, views7, views30, loginsToday, failsToday, recent] = await Promise.all([
      supabase.from('users').select('id', { count: 'exact', head: true }),
      supabase.from('users').select('id', { count: 'exact', head: true }).eq('is_blocked', true),
      supabase.from('audit_logs').select('user_id').eq('action', 'login').gte('timestamp', today),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').gte('timestamp', today),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').gte('timestamp', d7),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').gte('timestamp', d30),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'login').gte('timestamp', today),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'login_failed').gte('timestamp', today),
      supabase.from('audit_logs').select('*').order('timestamp', { ascending: false }).limit(25)
    ]);
    const activeIds = new Set((todayLogins.data || []).map(function (row) { return row.user_id; }).filter(Boolean));
    return res.json({
      stats: {
        totalUsers: total.count || 0,
        blockedUsers: blocked.count || 0,
        activeToday: activeIds.size,
        viewsToday: viewsToday.count || 0,
        views7: views7.count || 0,
        views30: views30.count || 0,
        loginsToday: loginsToday.count || 0,
        failsToday: failsToday.count || 0
      },
      recent: recent.data || []
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin users
router.get('/admin/users', authenticate, requireAdmin, async function (_req, res) {
  try {
    const result = await supabase.from('users')
      .select('id, username, role, page_access, is_blocked, blocked_by, blocked_at, blocked_reason, failed_login_attempts, last_failed_attempt, last_login, last_login_ip, last_login_device, login_status, created_at, updated_at')
      .order('created_at', { ascending: false });
    if (result.error) return res.status(500).json({ error: 'Could not load users' });
    return res.json({ users: result.data || [] });
  } catch (error) {
    console.error('List users error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/users/:id', authenticate, requireAdmin, async function (req, res) {
  try {
    const userResult = await findUserById(req.params.id);
    if (userResult.error || !userResult.data) return res.status(404).json({ error: 'Not found' });
    const [devices, logs] = await Promise.all([
      supabase.from('devices').select('*').eq('user_id', userResult.data.id).order('last_seen', { ascending: false }),
      supabase.from('audit_logs').select('*').eq('user_id', userResult.data.id).order('timestamp', { ascending: false }).limit(100)
    ]);
    const user = userResult.data;
    return res.json({
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        pageAccess: normalizePageAccess(user.page_access),
        is_blocked: user.is_blocked,
        blocked_by: user.blocked_by,
        blocked_at: user.blocked_at,
        blocked_reason: user.blocked_reason,
        failed_login_attempts: user.failed_login_attempts,
        last_login: user.last_login,
        last_login_ip: user.last_login_ip,
        last_login_device: user.last_login_device,
        login_status: user.login_status,
        created_at: user.created_at,
        devices: devices.data || []
      },
      logs: logs.data || []
    });
  } catch (error) {
    console.error('Get user error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users', authenticate, requireAdmin, async function (req, res) {
  try {
    const username = normalizeUsername(req.body && req.body.username);
    const password = req.body && req.body.password;
    if (!validUsername(username) || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Username + password (8+ chars) required.' });
    }
    const role = normalizeRole(req.body.role);
    const pageAccess = normalizePageAccess(req.body.pageAccess);
    const existing = await supabase.from('users').select('id').eq('username', username).maybeSingle();
    if (existing.data) return res.status(409).json({ error: 'Username exists.' });
    if (existing.error) return res.status(500).json({ error: 'Could not check username' });

    const insertResult = await supabase.from('users').insert({
      username,
      password: await bcrypt.hash(password, 12),
      role,
      page_access: pageAccess
    }).select('id, username, role, page_access, login_status, created_at').single();
    if (insertResult.error) return res.status(500).json({ error: 'Create failed' });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'user_created', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Created ' + username });
    return res.status(201).json({ success: true, user: insertResult.data });
  } catch (error) {
    console.error('Create user error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.put('/admin/users/:id', authenticate, requireAdmin, async function (req, res) {
  try {
    const update = {};
    if (Object.prototype.hasOwnProperty.call(req.body, 'role')) {
      if (!ALLOWED_ROLES.includes(req.body.role)) return res.status(400).json({ error: 'Invalid role' });
      update.role = req.body.role;
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'pageAccess')) update.page_access = normalizePageAccess(req.body.pageAccess);
    if (req.body.password !== undefined) {
      if (typeof req.body.password !== 'string' || req.body.password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
      update.password = await bcrypt.hash(req.body.password, 12);
    }
    if (Object.keys(update).length === 0) return res.status(400).json({ error: 'No changes supplied' });

    const result = await supabase.from('users').update(update).eq('id', req.params.id).select('id, username, role, page_access, login_status').single();
    if (result.error || !result.data) return res.status(404).json({ error: 'Not found' });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'user_updated', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Updated ' + result.data.username });
    return res.json({ success: true, user: result.data });
  } catch (error) {
    console.error('Update user error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.delete('/admin/users/:id', authenticate, requireAdmin, async function (req, res) {
  try {
    if (req.params.id === req.user._id) return res.status(400).json({ error: 'Cannot delete the current admin.' });
    const userResult = await supabase.from('users').select('username, role').eq('id', req.params.id).single();
    if (userResult.error || !userResult.data) return res.status(404).json({ error: 'Not found' });
    if (userResult.data.role === 'admin') return res.status(400).json({ error: 'Cannot delete admin.' });
    const deleted = await supabase.from('users').delete().eq('id', req.params.id);
    if (deleted.error) return res.status(500).json({ error: 'Delete failed' });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'user_deleted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Deleted ' + userResult.data.username });
    return res.json({ success: true });
  } catch (error) {
    console.error('Delete user error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

async function setUserBlocked(req, res, blocked) {
  const update = blocked ? {
    is_blocked: true,
    blocked_by: 'admin',
    blocked_at: new Date().toISOString(),
    blocked_reason: (req.body && req.body.reason) || 'Blocked by admin',
    login_status: 'blocked'
  } : {
    is_blocked: false,
    blocked_by: null,
    blocked_at: null,
    blocked_reason: null,
    failed_login_attempts: 0,
    login_status: 'inactive'
  };
  const result = await supabase.from('users').update(update).eq('id', req.params.id).select('username').single();
  if (result.error || !result.data) return res.status(404).json({ error: 'Not found' });
  await logActivity({ userId: req.user._id, username: req.user.username, action: blocked ? 'blocked' : 'unblocked', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: (blocked ? 'Blocked ' : 'Unblocked ') + result.data.username });
  return res.json({ success: true });
}

router.post('/admin/users/:id/block', authenticate, requireAdmin, async function (req, res) {
  try { return await setUserBlocked(req, res, true); }
  catch (error) { console.error('Block user error:', error); return res.status(500).json({ error: 'Server error' }); }
});

router.post('/admin/users/:id/unblock', authenticate, requireAdmin, async function (req, res) {
  try { return await setUserBlocked(req, res, false); }
  catch (error) { console.error('Unblock user error:', error); return res.status(500).json({ error: 'Server error' }); }
});

router.put('/admin/users/:id/access', authenticate, requireAdmin, async function (req, res) {
  try {
    const result = await supabase.from('users').update({ page_access: normalizePageAccess(req.body && req.body.pageAccess) })
      .eq('id', req.params.id).select('username, page_access').single();
    if (result.error || !result.data) return res.status(404).json({ error: 'Not found' });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'access_granted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Access for ' + result.data.username + ': ' + JSON.stringify(result.data.page_access) });
    return res.json({ success: true, user: result.data });
  } catch (error) {
    console.error('Update access error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin devices
async function setDeviceBlocked(req, res, blocked) {
  const result = await supabase.from('devices').update({ is_blocked: blocked })
    .eq('id', req.params.did).eq('user_id', req.params.uid).select('id').maybeSingle();
  if (result.error || !result.data) return res.status(404).json({ error: 'Device not found' });
  await logActivity({ userId: req.user._id, username: req.user.username, action: blocked ? 'device_blocked' : 'device_unblocked', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: (blocked ? 'Blocked device ' : 'Unblocked device ') + req.params.did });
  return res.json({ success: true });
}

router.post('/admin/devices/:uid/:did/block', authenticate, requireAdmin, async function (req, res) {
  try { return await setDeviceBlocked(req, res, true); }
  catch (error) { console.error('Block device error:', error); return res.status(500).json({ error: 'Server error' }); }
});

router.post('/admin/devices/:uid/:did/unblock', authenticate, requireAdmin, async function (req, res) {
  try { return await setDeviceBlocked(req, res, false); }
  catch (error) { console.error('Unblock device error:', error); return res.status(500).json({ error: 'Server error' }); }
});

// Admin page statistics
router.get('/admin/stats/pages', authenticate, requireAdmin, async function (_req, res) {
  try {
    const today = todayStart();
    const d7 = dateDaysAgo(7);
    const d30 = dateDaysAgo(30);
    const stats = {};
    for (const page of ALLOWED_PAGES) {
      const [todayResult, weekResult, monthResult] = await Promise.all([
        supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').eq('page', page).gte('timestamp', today),
        supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').eq('page', page).gte('timestamp', d7),
        supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').eq('page', page).gte('timestamp', d30)
      ]);
      stats[page] = { today: todayResult.count || 0, sevenDay: weekResult.count || 0, thirtyDay: monthResult.count || 0 };
    }
    const rawResult = await supabase.from('audit_logs').select('page, timestamp').eq('action', 'page_view').gte('timestamp', d30).order('timestamp', { ascending: true });
    const dailyMap = {};
    for (const row of rawResult.data || []) {
      if (!row.timestamp || !row.page) continue;
      const key = row.timestamp.slice(0, 10) + '_' + row.page;
      if (!dailyMap[key]) dailyMap[key] = { date: row.timestamp.slice(0, 10), page: row.page, count: 0 };
      dailyMap[key].count += 1;
    }
    return res.json({ stats, daily: Object.values(dailyMap) });
  } catch (error) {
    console.error('Page stats error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin audit logs
router.get('/admin/logs', authenticate, requireAdmin, async function (req, res) {
  try {
    const parsedLimit = Number.parseInt(req.query.limit, 10);
    const parsedOffset = Number.parseInt(req.query.offset, 10);
    const limit = Math.min(Math.max(Number.isFinite(parsedLimit) ? parsedLimit : 100, 1), 500);
    const offset = Math.max(Number.isFinite(parsedOffset) ? parsedOffset : 0, 0);
    let query = supabase.from('audit_logs').select('*', { count: 'exact' }).order('timestamp', { ascending: false }).range(offset, offset + limit - 1);
    if (req.query.action) query = query.eq('action', String(req.query.action).slice(0, 100));
    if (req.query.page) query = query.eq('page', String(req.query.page).slice(0, 100));
    if (req.query.status) query = query.eq('status', String(req.query.status).slice(0, 100));
    if (req.query.username) query = query.ilike('username', '%' + String(req.query.username).slice(0, 100).replace(/[%_]/g, '') + '%');
    const result = await query;
    if (result.error) return res.status(500).json({ error: 'Could not load logs' });
    return res.json({ logs: result.data || [], total: result.count || 0, limit, offset });
  } catch (error) {
    console.error('Logs error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/devices', authenticate, requireAdmin, async function (_req, res) {
  try {
    const result = await supabase.from('devices')
      .select('id, user_id, name, ip, first_seen, last_seen, is_blocked, users(username)')
      .order('last_seen', { ascending: false });
    if (result.error) return res.status(500).json({ error: 'Could not load devices' });
    const devices = (result.data || []).map(function (device) {
      return {
        deviceId: device.id,
        userId: device.user_id,
        username: device.users ? device.users.username : 'unknown',
        name: device.name,
        ip: device.ip,
        firstSeen: device.first_seen,
        lastSeen: device.last_seen,
        isBlocked: device.is_blocked
      };
    });
    return res.json({ devices });
  } catch (error) {
    console.error('List devices error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
