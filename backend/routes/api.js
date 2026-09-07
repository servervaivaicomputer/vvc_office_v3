const express    = require('express');
const router     = express.Router();
const rateLimit  = require('express-rate-limit');
const { User, AuditLog }  = require('../database/database');
const { generateToken, getClientIP, parseDevice, authenticate, requireAdmin, logActivity, recordDevice, COOKIE_NAME } = require('../middleware/auth');

/* ─── Rate limiters ─── */
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX)||10, message: { error: 'Too many login attempts — try later.' }, standardHeaders: true, legacyHeaders: false });
const apiLimiter   = rateLimit({ windowMs: 15*60*1000, max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS)||100, standardHeaders: true, legacyHeaders: false });
router.use(apiLimiter);

const sanitize = s => typeof s === 'string' ? s.replace(/[<>&'"\/]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;',"'":'&#39;','"':'&quot;','/':'&#47;'}[c])) : '';

/* ======================== AUTH ======================== */

/* POST /api/auth/login */
router.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
    username = sanitize(String(username).trim().toLowerCase());

    const ip  = getClientIP(req);
    const dev = parseDevice(req);
    const max = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 10;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

    if (user.isBlocked) {
      await logActivity({ userId: user._id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'blocked', details: 'Attempt on blocked account' });
      return res.status(403).json({ error: 'Account blocked. Contact admin.' });
    }

    const devBlocked = user.devices.find(d => d.ip === ip && d.isBlocked);
    if (devBlocked) {
      await logActivity({ userId: user._id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'blocked', details: 'Blocked device' });
      return res.status(403).json({ error: 'This device is blocked.' });
    }

    const ok = await user.comparePassword(password);
    if (!ok) {
      user.failedLoginAttempts += 1;
      user.lastFailedAttempt = new Date();
      if (user.failedLoginAttempts >= max) {
        user.isBlocked = true; user.blockedBy = 'auto'; user.blockedAt = new Date();
        user.blockedReason = `Auto-blocked after ${max} failed attempts`; user.loginStatus = 'blocked';
        await logActivity({ userId: user._id, username: user.username, action: 'blocked', ip, device: dev.name, userAgent: dev.ua, status: 'blocked', details: `Auto-blocked (${max} fails)` });
      }
      await user.save();
      await logActivity({ userId: user._id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'failure', details: `Attempt ${user.failedLoginAttempts}/${max}` });
      return res.status(401).json({ error: 'Invalid credentials.', attemptsRemaining: Math.max(0, max - user.failedLoginAttempts) });
    }

    user.failedLoginAttempts = 0; user.lastLogin = new Date(); user.lastLoginIP = ip; user.lastLoginDevice = dev.name; user.loginStatus = 'active';
    await recordDevice(user, ip, dev);
    const token = generateToken(user);
    await logActivity({ userId: user._id, username: user.username, action: 'login', ip, device: dev.name, userAgent: dev.ua, status: 'success', details: 'Login OK' });
    return res.json({ success: true, token, user: { username: user.username, role: user.role, pageAccess: user.pageAccess } });
  } catch (e) { console.error('Login err:', e); return res.status(500).json({ error: 'Server error.' }); }
});

/* POST /api/auth/admin-login — identical flow, rejects non-admin */
router.post('/auth/admin-login', loginLimiter, async (req, res) => {
  try {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Credentials required.' });
    username = sanitize(String(username).trim().toLowerCase());
    const ip = getClientIP(req), dev = parseDevice(req), max = parseInt(process.env.MAX_FAILED_ATTEMPTS)||10;
    const user = await User.findOne({ username });
    if (!user || user.role !== 'admin') return res.status(401).json({ error: 'Invalid admin credentials.' });
    if (user.isBlocked) return res.status(403).json({ error: 'Admin account blocked.' });
    const ok = await user.comparePassword(password);
    if (!ok) {
      user.failedLoginAttempts += 1; user.lastFailedAttempt = new Date();
      if (user.failedLoginAttempts >= max) { user.isBlocked = true; user.blockedBy = 'auto'; user.blockedAt = new Date(); user.blockedReason = 'Auto-blocked'; user.loginStatus = 'blocked'; }
      await user.save();
      await logActivity({ userId: user._id, username: user.username, action: 'login_failed', ip, device: dev.name, userAgent: dev.ua, status: 'failure', details: 'Admin login fail' });
      return res.status(401).json({ error: 'Invalid admin credentials.' });
    }
    user.failedLoginAttempts = 0; user.lastLogin = new Date(); user.lastLoginIP = ip; user.lastLoginDevice = dev.name; user.loginStatus = 'active';
    await recordDevice(user, ip, dev);
    const token = generateToken(user);
    await logActivity({ userId: user._id, username: user.username, action: 'login', ip, device: dev.name, userAgent: dev.ua, status: 'success', details: 'Admin login OK' });
    return res.json({ success: true, token, user: { username: user.username, role: user.role } });
  } catch (e) { console.error('Admin login err:', e); return res.status(500).json({ error: 'Server error.' }); }
});

/* POST /api/auth/logout */
router.post('/auth/logout', authenticate, async (req, res) => {
  await logActivity({ userId: req.user._id, username: req.user.username, action: 'logout', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ success: true });
});

/* GET /api/auth/me */
router.get('/auth/me', authenticate, (req, res) => {
  res.json({ user: { id: req.user._id, username: req.user.username, role: req.user.role, pageAccess: req.user.pageAccess, lastLogin: req.user.lastLogin, loginStatus: req.user.loginStatus } });
});

/* ======================== ADMIN ======================== */

/* Dashboard stats */
router.get('/admin/dashboard', authenticate, requireAdmin, async (_req, res) => {
  try {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const d7 = new Date(now - 7*864e5), d30 = new Date(now - 30*864e5);
    const [totalUsers, blockedUsers, activeToday, viewsToday, views7, views30, loginsToday, failsToday, recent] = await Promise.all([
      User.countDocuments(), User.countDocuments({ isBlocked: true }),
      AuditLog.distinct('userId', { action: 'login', timestamp: { $gte: today } }).then(a => a.length),
      AuditLog.countDocuments({ action: 'page_view', timestamp: { $gte: today } }),
      AuditLog.countDocuments({ action: 'page_view', timestamp: { $gte: d7 } }),
      AuditLog.countDocuments({ action: 'page_view', timestamp: { $gte: d30 } }),
      AuditLog.countDocuments({ action: 'login', timestamp: { $gte: today } }),
      AuditLog.countDocuments({ action: 'login_failed', timestamp: { $gte: today } }),
      AuditLog.find().sort({ timestamp: -1 }).limit(25).lean()
    ]);
    res.json({ stats: { totalUsers, blockedUsers, activeToday, viewsToday, views7, views30, loginsToday, failsToday }, recent });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* List users */
router.get('/admin/users', authenticate, requireAdmin, async (_req, res) => {
  try { res.json({ users: await User.find().select('-password').sort({ createdAt: -1 }).lean() }); }
  catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Single user + logs */
router.get('/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password').lean();
    if (!user) return res.status(404).json({ error: 'Not found' });
    const logs = await AuditLog.find({ userId: user._id }).sort({ timestamp: -1 }).limit(100).lean();
    res.json({ user, logs });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Create user */
router.post('/admin/users', authenticate, requireAdmin, async (req, res) => {
  try {
    let { username, password, role, pageAccess } = req.body;
    if (!username || !password || password.length < 8) return res.status(400).json({ error: 'Username + password (≥8 chars) required.' });
    username = sanitize(String(username).trim().toLowerCase());
    if (await User.findOne({ username })) return res.status(409).json({ error: 'Username exists.' });
    const u = await User.create({ username, password, role: role || 'user', pageAccess: pageAccess || [] });
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'user_created', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: `Created ${u.username}` });
    const obj = u.toObject(); delete obj.password;
    res.status(201).json({ success: true, user: obj });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Update user */
router.put('/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    const { role, pageAccess, password } = req.body;
    if (role) user.role = role;
    if (pageAccess) user.pageAccess = pageAccess;
    if (password && password.length >= 8) { user.password = password; }
    await user.save();
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'access_granted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: `Updated ${user.username}` });
    const obj = user.toObject(); delete obj.password;
    res.json({ success: true, user: obj });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Delete user */
router.delete('/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const u = await User.findById(req.params.id);
    if (!u) return res.status(404).json({ error: 'Not found' });
    if (u.role === 'admin') return res.status(400).json({ error: 'Cannot delete admin.' });
    await User.findByIdAndDelete(req.params.id);
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'user_deleted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: `Deleted ${u.username}` });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Block / Unblock user */
router.post('/admin/users/:id/block', authenticate, requireAdmin, async (req, res) => {
  try {
    const u = await User.findById(req.params.id); if (!u) return res.status(404).json({ error: 'Not found' });
    u.isBlocked = true; u.blockedBy = 'admin'; u.blockedAt = new Date(); u.blockedReason = req.body.reason || 'Blocked by admin'; u.loginStatus = 'blocked';
    await u.save();
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'blocked', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: `Blocked ${u.username}` });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

router.post('/admin/users/:id/unblock', authenticate, requireAdmin, async (req, res) => {
  try {
    const u = await User.findById(req.params.id); if (!u) return res.status(404).json({ error: 'Not found' });
    u.isBlocked = false; u.blockedBy = null; u.blockedAt = null; u.blockedReason = null; u.failedLoginAttempts = 0; u.loginStatus = 'inactive';
    await u.save();
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'unblocked', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: `Unblocked ${u.username}` });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Page access */
router.put('/admin/users/:id/access', authenticate, requireAdmin, async (req, res) => {
  try {
    const u = await User.findById(req.params.id); if (!u) return res.status(404).json({ error: 'Not found' });
    u.pageAccess = req.body.pageAccess || []; await u.save();
    await logActivity({ userId: req.user._id, username: req.user.username, action: 'access_granted', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, details: `Access for ${u.username}: [${u.pageAccess}]` });
    res.json({ success: true, pageAccess: u.pageAccess });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Block / Unblock device */
router.post('/admin/devices/:uid/:did/block', authenticate, requireAdmin, async (req, res) => {
  try {
    const u = await User.findById(req.params.uid); if (!u) return res.status(404).json({ error: 'Not found' });
    const d = u.devices.id(req.params.did); if (!d) return res.status(404).json({ error: 'Device not found' });
    d.isBlocked = true; await u.save(); res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

router.post('/admin/devices/:uid/:did/unblock', authenticate, requireAdmin, async (req, res) => {
  try {
    const u = await User.findById(req.params.uid); if (!u) return res.status(404).json({ error: 'Not found' });
    const d = u.devices.id(req.params.did); if (!d) return res.status(404).json({ error: 'Device not found' });
    d.isBlocked = false; await u.save(); res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Page statistics */
router.get('/admin/stats/pages', authenticate, requireAdmin, async (_req, res) => {
  try {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const d7 = new Date(now - 7*864e5), d30 = new Date(now - 30*864e5);
    const pages = ['home', 'about', 'workspace'];
    const stats = {};
    for (const p of pages) {
      const [t, w, m] = await Promise.all([
        AuditLog.countDocuments({ action: 'page_view', page: p, timestamp: { $gte: today } }),
        AuditLog.countDocuments({ action: 'page_view', page: p, timestamp: { $gte: d7 } }),
        AuditLog.countDocuments({ action: 'page_view', page: p, timestamp: { $gte: d30 } })
      ]);
      stats[p] = { today: t, sevenDay: w, thirtyDay: m };
    }
    const daily = await AuditLog.aggregate([
      { $match: { action: 'page_view', timestamp: { $gte: d30 } } },
      { $group: { _id: { date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }, page: '$page' }, count: { $sum: 1 } } },
      { $sort: { '_id.date': 1 } }
    ]);
    res.json({ stats, daily });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Logs */
router.get('/admin/logs', authenticate, requireAdmin, async (req, res) => {
  try {
    const { action, username, page, status, limit: lim, offset: off } = req.query;
    const filter = {};
    if (action)   filter.action   = action;
    if (username) filter.username = { $regex: username, $options: 'i' };
    if (page)     filter.page     = page;
    if (status)   filter.status   = status;
    const limit  = Math.min(parseInt(lim) || 100, 500);
    const offset = parseInt(off) || 0;
    const [logs, total] = await Promise.all([
      AuditLog.find(filter).sort({ timestamp: -1 }).skip(offset).limit(limit).lean(),
      AuditLog.countDocuments(filter)
    ]);
    res.json({ logs, total, limit, offset });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

/* Devices */
router.get('/admin/devices', authenticate, requireAdmin, async (_req, res) => {
  try {
    const users = await User.find({ 'devices.0': { $exists: true } }).select('username devices').lean();
    const all = [];
    users.forEach(u => u.devices.forEach(d => all.push({ userId: u._id, username: u.username, deviceId: d._id, name: d.name, ip: d.ip, firstSeen: d.firstSeen, lastSeen: d.lastSeen, isBlocked: d.isBlocked })));
    res.json({ devices: all });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

module.exports = router;
