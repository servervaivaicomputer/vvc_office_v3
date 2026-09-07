const express   = require('express');
const router    = express.Router();
const rateLimit = require('express-rate-limit');
const bcrypt    = require('bcryptjs');
const path      = require('path');
const fs        = require('fs');
const { supabase } = require('../database/database');
const {
  generateToken, getClientIP, parseDevice,
  authenticate, requireAdmin,
  logActivity, recordDevice, COOKIE_NAME
} = require('../middleware/auth');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 10,
  message: { error: 'Too many login attempts' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  standardHeaders: true,
  legacyHeaders: false
});
router.use(apiLimiter);

const sanitize = s => typeof s === 'string' ? s.replace(/[<>&'"\/]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;',"'":'&#39;','"':'&quot;','/':'&#47;'}[c])) : '';

/* ═══ AUTH ═══ */

router.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
    username = sanitize(String(username).trim().toLowerCase());
    const ip = getClientIP(req);
    const dev = parseDevice(req);
    const max = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 10;

    const { data: user, error: findErr } = await supabase.from('users').select('*').eq('username', username).single();
    if (findErr || !user) return res.status(401).json({ error: 'Invalid credentials.' });

    if (user.is_blocked) {
      await logActivity({ userId: user.id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'blocked', details: 'Blocked account' });
      return res.status(403).json({ error: 'Account blocked. Contact admin.' });
    }

    const { data: devBlocked } = await supabase.from('devices').select('id').eq('user_id', user.id).eq('ip', ip).eq('is_blocked', true).single();
    if (devBlocked) {
      await logActivity({ userId: user.id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'blocked', details: 'Blocked device' });
      return res.status(403).json({ error: 'This device is blocked.' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      const updateData = { failed_login_attempts: newAttempts, last_failed_attempt: new Date().toISOString() };
      if (newAttempts >= max) {
        updateData.is_blocked = true;
        updateData.blocked_by = 'auto';
        updateData.blocked_at = new Date().toISOString();
        updateData.blocked_reason = 'Auto-blocked after ' + max + ' failed attempts';
        updateData.login_status = 'blocked';
        await logActivity({ userId: user.id, username: user.username, action: 'blocked', ip, device: dev.name, userAgent: dev.ua, status: 'blocked', details: 'Auto-blocked (' + max + ' fails)' });
      }
      await supabase.from('users').update(updateData).eq('id', user.id);
      await logActivity({ userId: user.id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'failure', details: 'Attempt ' + newAttempts + '/' + max });
      return res.status(401).json({ error: 'Invalid credentials.', attemptsRemaining: Math.max(0, max - newAttempts) });
    }

    const normUser = { id: user.id, username: user.username, role: user.role, pageAccess: user.page_access || [] };
    await supabase.from('users').update({ failed_login_attempts: 0, last_login: new Date().toISOString(), last_login_ip: ip, last_login_device: dev.name, login_status: 'active' }).eq('id', user.id);
    await recordDevice(normUser, ip, dev);
    const token = generateToken(normUser);
    await logActivity({ userId: user.id, username: user.username, action: 'login', ip, device: dev.name, userAgent: dev.ua, status: 'success', details: 'Login OK' });
    return res.json({ success: true, token, user: { username: user.username, role: user.role, pageAccess: user.page_access || [] } });
  } catch (e) {
    console.error('Login err:', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

router.post('/auth/admin-login', loginLimiter, async (req, res) => {
  try {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Credentials required.' });
    username = sanitize(String(username).trim().toLowerCase());
    const ip = getClientIP(req);
    const dev = parseDevice(req);
    const max = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 10;

    const { data: user } = await supabase.from('users').select('*').eq('username', username).single();
    if (!user || user.role !== 'admin') return res.status(401).json({ error: 'Invalid admin credentials.' });
    if (user.is_blocked) return res.status(403).json({ error: 'Admin account blocked.' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      const updateData = { failed_login_attempts: newAttempts, last_failed_attempt: new Date().toISOString() };
      if (newAttempts >= max) {
        updateData.is_blocked = true;
        updateData.blocked_by = 'auto';
        updateData.blocked_at = new Date().toISOString();
        updateData.blocked_reason = 'Auto-blocked';
        updateData.login_status = 'blocked';
      }
      await supabase.from('users').update(updateData).eq('id', user.id);
      await logActivity({ userId: user.id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'failure', details: 'Admin login fail' });
      return res.status(401).json({ error: 'Invalid admin credentials.' });
    }

    const normUser = { id: user.id, username: user.username, role: user.role, pageAccess: user.page_access || [] };
    await supabase.from('users').update({ failed_login_attempts: 0, last_login: new Date().toISOString(), last_login_ip: ip, last_login_device: dev.name, login_status: 'active' }).eq('id', user.id);
    await recordDevice(normUser, ip, dev);
    const token = generateToken(normUser);
    await logActivity({ userId: user.id, username: user.username, action: 'login', ip, device: dev.name, userAgent: dev.ua, status: 'success', details: 'Admin login OK' });
    return res.json({ success: true, token, user: { username: user.username, role: user.role } });
  } catch (e) {
    console.error('Admin login err:', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

router.post('/auth/logout', authenticate, async (req, res) => {
  await logActivity({ userId: req.user._id, username: req.user.username, action: 'logout', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ success: true });
});

router.get('/auth/me', authenticate, (req, res) => {
  res.json({ user: { id: req.user._id, username: req.user.username, role: req.user.role, pageAccess: req.user.pageAccess, lastLogin: req.user.lastLogin, loginStatus: req.user.loginStatus } });
});

/* ═══ PAGE CONTENT API ═══ */

router.get('/pages/:pageName', authenticate, async (req, res) => {
  try {
    const page = req.params.pageName;
    const allowed = ['home', 'about', 'workspace', 'landing'];
    if (!allowed.includes(page)) return res.status(404).json({ error: 'Page not found' });
    if (req.user.role !== 'admin' && !req.user.pageAccess.includes(page)) return res.status(403).json({ error: 'Access denied', page });

    const fp = path.join(__dirname, '..', 'projects', page, 'index.html');
    if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Page file not found' });

    let html = fs.readFileSync(fp, 'utf8');
    html = html
      .replace(/\{\{USERNAME\}\}/g, req.user.username)
      .replace(/\{\{ROLE\}\}/g, req.user.role)
      .replace(/\{\{USER_PAGES\}\}/g, JSON.stringify(req.user.pageAccess))
      .replace(/\{\{FRONTEND_URL\}\}/g, process.env.FRONTEND_URL);

    await logActivity({ userId: req.user._id, username: req.user.username, action: 'page_view', page, ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    console.error('Page serve err:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/pages/admin/panel', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const fp = path.join(__dirname, '..', 'admin', 'index.html');
    if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });

    let html = fs.readFileSync(fp, 'utf8');
    const backendUrl = req.protocol + '://' + req.get('host');
    const authToken = (req.headers['authorization'] || '').replace('Bearer ', '');

    html = html
      .replace(/\{\{USERNAME\}\}/g, req.user.username)
      .replace(/\{\{FRONTEND_URL\}\}/g, process.env.FRONTEND_URL)
      .replace(/\{\{BACKEND_URL\}\}/g, backendUrl)
      .replace(/\{\{AUTH_TOKEN\}\}/g, authToken);

    await logActivity({ userId: req.user._id, username: req.user.username, action: 'page_view', page: 'admin', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    console.error('Admin panel err:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ═══ ADMIN ═══ */

router.get('/admin/dashboard', authenticate, requireAdmin, async (_req, res) => {
  try {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const d7 = new Date(now - 7 * 864e5).toISOString();
    const d30 = new Date(now - 30 * 864e5).toISOString();

    const [
      { count: totalUsers },
      { count: blockedUsers },
      { data: todayLogins },
      { count: viewsToday },
      { count: views7 },
      { count: views30 },
      { count: loginsToday },
      { count: failsToday },
      { data: recent }
    ] = await Promise.all([
      supabase.from('users').select('id', { count: 'exact', head: true }),
      supabase.from('users').select('id', { count: 'exact', head: true }).eq('is_blocked', true),
      supabasegte('timestamp', today),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').gte('timestamp', today),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').gte('timestamp', d7),
      supabase.from('audit_logs').select('id', { count.from('audit_logs').select('user_id', { count: 'exact' }).eq('action', 'login').: 'exact', head: true }).eq('action', 'page_view').gte('timestamp', d30),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'login').gte('timestamp', today),
      supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'login_failed').gte('timestamp', today),
      supabase.from('audit_logs').select('*').order('timestamp', { ascending: false }).limit(25)
    ]);

    const activeToday = todayLogins ? [...new Set(todayLogins.map(l => l.user_id))].length : 0;
    res.json({ stats: { totalUsers: totalUsers || 0, blockedUsers: blockedUsers || 0, activeToday, viewsToday: viewsToday || 0, views7: views7 || 0, views30: views30 || 0, loginsToday: loginsToday || 0, failsToday: failsToday || 0 }, recent: recent || [] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/users', authenticate, requireAdmin, async (_req, res) => {
  try {
    const { data: users } = await supabase.from('users').select('id, username, role, page_access, is_blocked, blocked_by, blocked_at, blocked_reason, failed_login_attempts, last_failed_attempt, last_login, last_login_ip, last_login_device, login_status, created_at, updated_at').order('created_at', { ascending: false });
    res.json({ users: users || [] });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('id, username, role, page_access, is_blocked, blocked_by, blocked_at, blocked_reason, failed_login_attempts, last_login, last_login_ip, last_login_device, login_status, created_at').eq('id', req.params.id).single();
    if (!user) return res.status(404).json({ error: 'Not found' });
    const { data: devices } = await supabase.from('devices').select('*').eq('user_id', user.id).order('last_seen', { ascending: false });
    const { data: logs } = await supabase.from('audit_logs').select('*').eq('user_id', user.id).order('timestamp', { ascending: false }).limit(100);
    res.json({ user: { ...user, pageAccess: user.page_access || [], devices: devices || [] }, logs: logs || [] });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users', authenticate, requireAdmin, async (req, res) => {
  try {
    let { username, password, role, pageAccess } = req.body;
    if (!username || !password || password.length < 8) return res.status(400).json({ error: 'Username + password (8+ chars) required.' });
    username = sanitize(String(username).trim().toLowerCase());
    const { data: exists } = await supabase.from('users').select('id').eq('username', username).single();
    if (exists) return res.status(409).json({ error: 'Username exists.' });
    const hashed = await bcrypt.hash(password, 12);
    const { data: newUser, error } = await supabase.from('users').insert({ username: username, password: hashed, role: role || 'user', page_access: pageAccess || [] }).select('id, username, role, page_access, login_status, created_at').single();
    if (error) return res.status(500).json({ error: 'Create failed' });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'user_created', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Created ' + username });
    res.status(201).json({ success: true, user: newUser });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { role, pageAccess, password } = req.body;
    const updateData = {};
    if (role) updateData.role = role;
    if (pageAccess) updateData.page_access = pageAccess;
    if (password && password.length >= 8) updateData.password = await bcrypt.hash(password, 12);
    const { data: updated, error } = await supabase.from('users').update(updateData).eq('id', req.params.id).select('id, username, role, page_access, login_status').single();
    if (error || !updated) return res.status(404).json({ error: 'Not found' });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'access_granted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Updated ' + updated.username });
    res.json({ success: true, user: updated });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.delete('/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data: u } = await supabase.from('users').select('username, role').eq('id', req.params.id).single();
    if (!u) return res.status(404).json({ error: 'Not found' });
    if (u.role === 'admin') return res.status(400).json({ error: 'Cannot delete admin.' });
    await supabase.from('users').delete().eq('id', req.params.id);
    await logActivity({ userId: req.user._id, username: req.user.username: new Date().toISOString(), blocked_reason: req.body.reason || 'Blocked by admin', login_status: 'blocked' }).eq('id', req.params.id);
    const { data: u } = await supabase.from('users').select('username').eq('id', req.params.id).single();
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'blocked', ip: req.clientIP, device: req.deviceInfo.name, userAgent:    await supabase.from('users').update({ is_blocked: true, blocked_by: 'admin', blocked_at, action: 'user_deleted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Deleted ' + u.username });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users/:id/block', authenticate, requireAdmin, async (req, res) => {
  try {
 req.deviceInfo.ua, details: 'Blocked ' + (u ? u.username : req.params.id) });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users/:id/unblock', authenticate, requireAdmin, async (req, res) => {
  try {
    await supabase.from('users').update({ is_blocked: false, blocked_by: null, blocked_at: null, blocked_reason: null, failed_login_attempts: 0, login_status: 'inactive' }).eq('id', req.params.id);
    const { data: u } = await supabase.from('users').select('username').eq('id', req.params.id).single();
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'unblocked', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Unblocked ' + (u ? u.username : req.params.id) });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/admin/users/:id/access', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data: u } = await supabase.from('users').update({ page_access: req.body.pageAccess || [] }).eq('id', req.params.id).select('username, page_access').single();
    if (!u) return res.status(404).json({ error: 'Not found' });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'access_granted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: 'Access for ' + u.username + ': ' + JSON.stringify(u.page_access) });
    res.json({ success: true, pageAccess: u.page_access });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/devices/:uid/:did/block', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('devices').update({ is_blocked: true }).eq('id', req.params.did).eq('user_id', req.params.uid);
    if (error) return res.status(404).json({ error: 'Device not found' });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/devices/:uid/:did/unblock', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('devices').update({ is_blocked: false }).eq('id', req.params.did).eq('user_id', req.params.uid);
    if (error) return res.status(404).json({ error: 'Device not found' });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/stats/pages', authenticate, requireAdmin, async (_req, res) => {
  try {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const d7 = new Date(now - 7 * 864e5).toISOString();
    const d30 = new Date(now - 30 * 864e5).toISOString();
    const pages = ['home', 'about', 'workspace', 'landing'];
    const stats = {};

    for (const p of pages) {
      const [{ count: t }, { count: w }, { count: m }] = await Promise.all([
        supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').eq('page', p).gte('timestamp', today),
        supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').eq('page', p).gte('timestamp', d7),
        supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('action', 'page_view').eq('page', p).gte('timestamp', d30)
      ]);
      stats[p] = { today: t || 0, sevenDay: w || 0, thirtyDay: m || 0 };
    }

    const { data: raw } = await supabase.from('audit_logs').select('page, timestamp').eq('action', 'page_view').gte('timestamp', d30).order('timestamp', { ascending: true });
    const dailyMap = {};
    (raw || []).forEach(r => {
      const date = r.timestamp.substring(0, 10);
      const key = date + '_' + r.page;
      if (!dailyMap[key]) dailyMap[key] = { date: date, page: r.page, count: 0 };
      dailyMap[key].count++;
    });
    res.json({ stats, daily: Object.values(dailyMap) });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/logs', authenticate, requireAdmin, async (req, res) => {
  try {
    const { action, username, page, status, limit: lim, offset: off } = req.query;
    const limit = Math.min(parseInt(lim) || 100, 500);
    const offset = parseInt(off) || 0;
    let query = supabase.from('audit_logs').select('*', { count: 'exact' }).order('timestamp', { ascending: false }).range(offset, offset + limit - , firstSeen: d.first_seen, lastSeen: d.last_seen, isBlocked: d.is_blocked }));
    res.json({ devices: all });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
