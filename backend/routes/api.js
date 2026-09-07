const express = require('express');
const router = express.Router();
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

function sanitize(s) {
  if (typeof s !== 'string') return '';
  var map = {
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    "'": '&#39;',
    '"': '&quot;',
    '/': '&#47;'
  };
  return s.replace(/[<>&'"\/]/g, function(c) {
    return map[c];
  });
}

/* ──────── AUTH ──────── */

router.post('/auth/login', loginLimiter, async function(req, res) {
  try {
    var username = req.body.username;
    var password = req.body.password;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required.' });
    }
    username = sanitize(String(username).trim().toLowerCase());

    var ip = getClientIP(req);
    var dev = parseDevice(req);
    var max = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 10;

    var result = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    var user = result.data;
    if (result.error || !user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (user.is_blocked) {
      await logActivity({
        userId: user.id,
        username: user.username,
        action: 'login_failed',
        ip: ip,
        device: dev.name,
        userAgent: dev.ua,
        status: 'blocked',
        details: 'Blocked account'
      });
      return res.status(403).json({ error: 'Account blocked. Contact admin.' });
    }

    var devResult = await supabase
      .from('devices')
      .select('id')
      .eq('user_id', user.id)
      .eq('ip', ip)
      .eq('is_blocked', true)
      .single();

    if (devResult.data) {
      await logActivity({
        userId: user.id,
        username: user.username,
        action: 'login_failed',
        ip: ip,
        device: dev.name,
        userAgent: dev.ua,
        status: 'blocked',
        details: 'Blocked device'
      });
      return res.status(403).json({ error: 'This device is blocked.' });
    }

    var ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      var newAttempts = (user.failed_login_attempts || 0) + 1;
      var updateData = {
        failed_login_attempts: newAttempts,
        last_failed_attempt: new Date().toISOString()
      };
      if (newAttempts >= max) {
        updateData.is_blocked = true;
        updateData.blocked_by = 'auto';
        updateData.blocked_at = new Date().toISOString();
        updateData.blocked_reason = 'Auto-blocked after ' + max + ' failed attempts';
        updateData.login_status = 'blocked';
        await logActivity({
          userId: user.id,
          username: user.username,
          action: 'blocked',
          ip: ip,
          device: dev.name,
          userAgent: dev.ua,
          status: 'blocked',
          details: 'Auto-blocked (' + max + ' fails)'
        });
      }
      await supabase
        .from('users')
        .update(updateData)
        .eq('id', user.id);
      await logActivity({
        userId: user.id,
        username: user.username,
        action: 'login_failed',
        ip: ip,
        device: dev.name,
        userAgent: dev.ua,
        status: 'failure',
        details: 'Attempt ' + newAttempts + '/' + max
      });
      return res.status(401).json({
        error: 'Invalid credentials.',
        attemptsRemaining: Math.max(0, max - newAttempts)
      });
    }

    var normUser = {
      id: user.id,
      username: user.username,
      role: user.role,
      pageAccess: user.page_access || []
    };

    await supabase
      .from('users')
      .update({
        failed_login_attempts: 0,
        last_login: new Date().toISOString(),
        last_login_ip: ip,
        last_login_device: dev.name,
        login_status: 'active'
      })
      .eq('id', user.id);

    await recordDevice(normUser, ip, dev);
    var token = generateToken(normUser);

    await logActivity({
      userId: user.id,
      username: user.username,
      action: 'login',
      ip: ip,
      device: dev.name,
      userAgent: dev.ua,
      status: 'success',
      details: 'Login OK'
    });

    return res.json({
      success: true,
      token: token,
      user: {
        username: user.username,
        role: user.role,
        pageAccess: user.page_access || []
      }
    });
  } catch (e) {
    console.error('Login err:', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

router.post('/auth/admin-login', loginLimiter, async function(req, res) {
  try {
    var username = req.body.username;
    var password = req.body.password;
    if (!username || !password) {
      return res.status(400).json({ error: 'Credentials required.' });
    }
    username = sanitize(String(username).trim().toLowerCase());

    var ip = getClientIP(req);
    var dev = parseDevice(req);
    var max = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 10;

    var result = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    var user = result.data;
    if (!user || user.role !== 'admin') {
      return res.status(401).json({ error: 'Invalid admin credentials.' });
    }
    if (user.is_blocked) {
      return res.status(403).json({ error: 'Admin account blocked.' });
    }

    var ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      var newAttempts = (user.failed_login_attempts || 0) + 1;
      var updateData = {
        failed_login_attempts: newAttempts,
        last_failed_attempt: new Date().toISOString()
      };
      if (newAttempts >= max) {
        updateData.is_blocked = true;
        updateData.blocked_by = 'auto';
        updateData.blocked_at = new Date().toISOString();
        updateData.blocked_reason = 'Auto-blocked';
        updateData.login_status = 'blocked';
      }
      await supabase
        .from('users')
        .update(updateData)
        .eq('id', user.id);
      await logActivity({
        userId: user.id,
        username: user.username,
        action: 'login_failed',
        ip: ip,
        device: dev.name,
        userAgent: dev.ua,
        status: 'failure',
        details: 'Admin login fail'
      });
      return res.status(401).json({ error: 'Invalid admin credentials.' });
    }

    var normUser = {
      id: user.id,
      username: user.username,
      role: user.role,
      pageAccess: user.page_access || []
    };

    await supabase
      .from('users')
      .update({
        failed_login_attempts: 0,
        last_login: new Date().toISOString(),
        last_login_ip: ip,
        last_login_device: dev.name,
        login_status: 'active'
      })
      .eq('id', user.id);

    await recordDevice(normUser, ip, dev);
    var token = generateToken(normUser);

    await logActivity({
      userId: user.id,
      username: user.username,
      action: 'login',
      ip: ip,
      device: dev.name,
      userAgent: dev.ua,
      status: 'success',
      details: 'Admin login OK'
    });

    return res.json({
      success: true,
      token: token,
      user: { username: user.username, role: user.role }
    });
  } catch (e) {
    console.error('Admin login err:', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

router.post('/auth/logout', authenticate, async function(req, res) {
  await logActivity({
    userId: req.user._id,
    username: req.user.username,
    action: 'logout',
    ip: req.clientIP,
    device: req.deviceInfo.name,
    userAgent: req.deviceInfo.ua,
    status: 'success'
  });
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ success: true });
});

router.get('/auth/me', authenticate, function(req, res) {
  res.json({
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

/* ──────── PAGE CONTENT ──────── */

router.get('/pages/:pageName', authenticate, async function(req, res) {
  try {
    var page = req.params.pageName;
    var allowed = ['home', 'about', 'workspace', 'landing'];
    if (allowed.indexOf(page) === -1) {
      return res.status(404).json({ error: 'Page not found' });
    }
    if (req.user.role !== 'admin' && req.user.pageAccess.indexOf(page) === -1) {
      return res.status(403).json({ error: 'Access denied', page: page });
    }

    var fp = path.join(__dirname, '..', 'projects', page, 'index.html');
    if (!fs.existsSync(fp)) {
      return res.status(404).json({ error: 'Page file not found' });
    }

    var html = fs.readFileSync(fp, 'utf8');
    html = html.replace(/\{\{USERNAME\}\}/g, req.user.username);
    html = html.replace(/\{\{ROLE\}\}/g, req.user.role);
    html = html.replace(/\{\{USER_PAGES\}\}/g, JSON.stringify(req.user.pageAccess));
    html = html.replace(/\{\{FRONTEND_URL\}\}/g, process.env.FRONTEND_URL);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'page_view',
      page: page,
      ip: req.clientIP,
      device: req.deviceInfo.name,
      userAgent: req.deviceInfo.ua,
      status: 'success'
    });

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    console.error('Page serve err:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────── ADMIN DASHBOARD ──────── */

router.get('/admin/dashboard', authenticate, requireAdmin, async function(_req, res) {
  try {
    var now = new Date();
    var today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    var d7 = new Date(now - 7 * 864e5).toISOString();
    var d30 = new Date(now - 30 * 864e5).toISOString();

    var r1 = await supabase
      .from('users')
      .select('id', { count: 'exact', head: true });

    var r2 = await supabase
      .from('users')
      .select('id', { count: 'exact', head: true })
      .eq('is_blocked', true);

    var r3 = await supabase
      .from('audit_logs')
      .select('user_id', { count: 'exact' })
      .eq('action', 'login')
      .gte('timestamp', today);

    var r4 = await supabase
      .from('audit_logs')
      .select('id', { count: 'exact', head: true })
      .eq('action', 'page_view')
      .gte('timestamp', today);

    var r5 = await supabase
      .from('audit_logs')
      .select('id', { count: 'exact', head: true })
      .eq('action', 'page_view')
      .gte('timestamp', d7);

    var r6 = await supabase
      .from('audit_logs')
      .select('id', { count: 'exact', head: true })
      .eq('action', 'page_view')
      .gte('timestamp', d30);

    var r7 = await supabase
      .from('audit_logs')
      .select('id', { count: 'exact', head: true })
      .eq('action', 'login')
      .gte('timestamp', today);

    var r8 = await supabase
      .from('audit_logs')
      .select('id', { count: 'exact', head: true })
      .eq('action', 'login_failed')
      .gte('timestamp', today);

    var r9 = await supabase
      .from('audit_logs')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(25);

    var todayLogins = r3.data || [];
    var userIds = todayLogins.map(function(l) { return l.user_id; });
    var uniqueIds = [];
    for (var i = 0; i < userIds.length; i++) {
      if (uniqueIds.indexOf(userIds[i]) === -1) {
        uniqueIds.push(userIds[i]);
      }
    }
    var activeToday = uniqueIds.length;

    res.json({
      stats: {
        totalUsers: r1.count || 0,
        blockedUsers: r2.count || 0,
        activeToday: activeToday,
        viewsToday: r4.count || 0,
        views7: r5.count || 0,
        views30: r6.count || 0,
        loginsToday: r7.count || 0,
        failsToday: r8.count || 0
      },
      recent: r9.data || []
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────── ADMIN USERS ──────── */

router.get('/admin/users', authenticate, requireAdmin, async function(_req, res) {
  try {
    var result = await supabase
      .from('users')
      .select('id, username, role, page_access, is_blocked, blocked_by, blocked_at, blocked_reason, failed_login_attempts, last_failed_attempt, last_login, last_login_ip, last_login_device, login_status, created_at, updated_at')
      .order('created_at', { ascending: false });

    res.json({ users: result.data || [] });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/users/:id', authenticate, requireAdmin, async function(req, res) {
  try {
    var userResult = await supabase
      .from('users')
      .select('id, username, role, page_access, is_blocked, blocked_by, blocked_at, blocked_reason, failed_login_attempts, last_login, last_login_ip, last_login_device, login_status, created_at')
      .eq('id', req.params.id)
      .single();

    if (!userResult.data) {
      return res.status(404).json({ error: 'Not found' });
    }

    var devResult = await supabase
      .from('devices')
      .select('*')
      .eq('user_id', userResult.data.id)
      .order('last_seen', { ascending: false });

    var logResult = await supabase
      .from('audit_logs')
      .select('*')
      .eq('user_id', userResult.data.id)
      .order('timestamp', { ascending: false })
      .limit(100);

    var u = userResult.data;
    res.json({
      user: {
        id: u.id,
        username: u.username,
        role: u.role,
        pageAccess: u.page_access || [],
        is_blocked: u.is_blocked,
        blocked_by: u.blocked_by,
        blocked_at: u.blocked_at,
        blocked_reason: u.blocked_reason,
        failed_login_attempts: u.failed_login_attempts,
        last_login: u.last_login,
        last_login_ip: u.last_login_ip,
        last_login_device: u.last_login_device,
        login_status: u.login_status,
        created_at: u.created_at,
        devices: devResult.data || []
      },
      logs: logResult.data || []
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users', authenticate, requireAdmin, async function(req, res) {
  try {
    var username = req.body.username;
    var password = req.body.password;
    var role = req.body.role;
    var pageAccess = req.body.pageAccess;

    if (!username || !password || password.length < 8) {
      return res.status(400).json({ error: 'Username + password (8+ chars) required.' });
    }
    username = sanitize(String(username).trim().toLowerCase());

    var existsResult = await supabase
      .from('users')
      .select('id')
      .eq('username', username)
      .single();

    if (existsResult.data) {
      return res.status(409).json({ error: 'Username exists.' });
    }

    var hashed = await bcrypt.hash(password, 12);
    var insertResult = await supabase
      .from('users')
      .insert({
        username: username,
        password: hashed,
        role: role || 'user',
        page_access: pageAccess || []
      })
      .select('id, username, role, page_access, login_status, created_at')
      .single();

    if (insertResult.error) {
      return res.status(500).json({ error: 'Create failed' });
    }

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'user_created',
      ip: req.clientIP,
      device: req.deviceInfo.name,
      userAgent: req.deviceInfo.ua,
      details: 'Created ' + username
    });

    res.status(201).json({ success: true, user: insertResult.data });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/admin/users/:id', authenticate, requireAdmin, async function(req, res) {
  try {
    var role = req.body.role;
    var pageAccess = req.body.pageAccess;
    var password = req.body.password;

    var updateData = {};
    if (role) updateData.role = role;
    if (pageAccess) updateData.page_access = pageAccess;
    if (password && password.length >= 8) {
      updateData.password = await bcrypt.hash(password, 12);
    }

    var result = await supabase
      .from('users')
      .update(updateData)
      .eq('id', req.params.id)
      .select('id, username, role, page_access, login_status')
      .single();

    if (result.error || !result.data) {
      return res.status(404).json({ error: 'Not found' });
    }

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'access_granted',
      ip: req.clientIP,
      device: req.deviceInfo.name,
      userAgent: req.deviceInfo.ua,
      details: 'Updated ' + result.data.username
    });

    res.json({ success: true, user: result.data });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.delete('/admin/users/:id', authenticate, requireAdmin, async function(req, res) {
  try {
    var userResult = await supabase
      .from('users')
      .select('username, role')
      .eq('id', req.params.id)
      .single();

    if (!userResult.data) {
      return res.status(404).json({ error: 'Not found' });
    }
    if (userResult.data.role === 'admin') {
      return res.status(400).json({ error: 'Cannot delete admin.' });
    }

    await supabase
      .from('users')
      .delete()
      .eq('id', req.params.id);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'user_deleted',
      ip: req.clientIP,
      device: req.deviceInfo.name,
      userAgent: req.deviceInfo.ua,
      details: 'Deleted ' + userResult.data.username
    });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users/:id/block', authenticate, requireAdmin, async function(req, res) {
  try {
    await supabase
      .from('users')
      .update({
        is_blocked: true,
        blocked_by: 'admin',
        blocked_at: new Date().toISOString(),
        blocked_reason: req.body.reason || 'Blocked by admin',
        login_status: 'blocked'
      })
      .eq('id', req.params.id);

    var userResult = await supabase
      .from('users')
      .select('username')
      .eq('id', req.params.id)
      .single();

    var name = userResult.data ? userResult.data.username : req.params.id;

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'blocked',
      ip: req.clientIP,
      device: req.deviceInfo.name,
      userAgent: req.deviceInfo.ua,
      details: 'Blocked ' + name
    });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users/:id/unblock', authenticate, requireAdmin, async function(req, res) {
  try {
    await supabase
      .from('users')
      .update({
        is_blocked: false,
        blocked_by: null,
        blocked_at: null,
        blocked_reason: null,
        failed_login_attempts: 0,
        login_status: 'inactive'
      })
      .eq('id', req.params.id);

    var userResult = await supabase
      .from('users')
      .select('username')
      .eq('id', req.params.id)
      .single();

    var name = userResult.data ? userResult.data.username : req.params.id;

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'unblocked',
      ip: req.clientIP,
      device: req.deviceInfo.name,
      userAgent: req.deviceInfo.ua,
      details: 'Unblocked ' + name
    });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/admin/users/:id/access', authenticate, requireAdmin, async function(req, res) {
  try {
    var result = await supabase
      .from('users')
      .update({ page_access: req.body.pageAccess || [] })
      .eq('id', req.params.id)
      .select('username, page_access')
      .single();

    if (!result.data) {
      return res.status(404).json({ error: 'Not found' });
    }

    var details = 'Access for ' + result.data.username + ': ' + JSON.stringify(result.data.page_access);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'access_granted',
      ip: req.clientIP,
      device: req.deviceInfo.name,
      userAgent: req.deviceInfo.ua,
      details: details
    });

    res.json({ success: true, pageAccess: result.data.page_access });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────── ADMIN DEVICES ──────── */

router.post('/admin/devices/:uid/:did/block', authenticate, requireAdmin, async function(req, res) {
  try {
    var result = await supabase
      .from('devices')
      .update({ is_blocked: true })
      .eq('id', req.params.did)
      .eq('user_id', req.params.uid);

    if (result.error) {
      return res.status(404).json({ error: 'Device not found' });
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/devices/:uid/:did/unblock', authenticate, requireAdmin, async function(req, res) {
  try {
    var result = await supabase
      .from('devices')
      .update({ is_blocked: false })
      .eq('id', req.params.did)
      .eq('user_id', req.params.uid);

    if (result.error) {
      return res.status(404).json({ error: 'Device not found' });
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────── ADMIN PAGE STATS ──────── */

router.get('/admin/stats/pages', authenticate, requireAdmin, async function(_req, res) {
  try {
    var now = new Date();
    var today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    var d7 = new Date(now - 7 * 864e5).toISOString();
    var d30 = new Date(now - 30 * 864e5).toISOString();
    var pages = ['home', 'about', 'workspace', 'landing'];
    var stats = {};

    for (var i = 0; i < pages.length; i++) {
      var p = pages[i];

      var tResult = await supabase
        .from('audit_logs')
        .select('id', { count: 'exact', head: true })
        .eq('action', 'page_view')
        .eq('page', p)
        .gte('timestamp', today);

      var wResult = await supabase
        .from('audit_logs')
        .select('id', { count: 'exact', head: true })
        .eq('action', 'page_view')
        .eq('page', p)
        .gte('timestamp', d7);

      var mResult = await supabase
        .from('audit_logs')
        .select('id', { count: 'exact', head: true })
        .eq('action', 'page_view')
        .eq('page', p)
        .gte('timestamp', d30);

      stats[p] = {
        today: tResult.count || 0,
        sevenDay: wResult.count || 0,
        thirtyDay: mResult.count || 0
      };
    }

    var rawResult = await supabase
      .from('audit_logs')
      .select('page, timestamp')
      .eq('action', 'page_view')
      .gte('timestamp', d30)
      .order('timestamp', { ascending: true });

    var dailyMap = {};
    var raw = rawResult.data || [];
    for (var j = 0; j < raw.length; j++) {
      var r = raw[j];
      var date = r.timestamp.substring(0, 10);
      var key = date + '_' + r.page;
      if (!dailyMap[key]) {
        dailyMap[key] = { date: date, page: r.page, count: 0 };
      }
      dailyMap[key].count++;
    }

    var daily = [];
    var keys = Object.keys(dailyMap);
    for (var k = 0; k < keys.length; k++) {
      daily.push(dailyMap[keys[k]]);
    }

    res.json({ stats: stats, daily: daily });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────── ADMIN LOGS ──────── */

router.get('/admin/logs', authenticate, requireAdmin, async function(req, res) {
  try {
    var action = req.query.action;
    var username = req.query.username;
    var page = req.query.page;
    var status = req.query.status;
    var lim = req.query.limit;
    var off = req.query.offset;

    var limit = Math.min(parseInt(lim) || 100, 500);
    var offset = parseInt(off) || 0;

    var query = supabase
      .from('audit_logs')
      .select('*', { count: 'exact' })
      .order('timestamp', { ascending: false })
      .range(offset, offset + limit - 1);

    if (action) query = query.eq('action', action);
    if (page) query = query.eq('page', page);
    if (status) query = query.eq('status', status);
    if (username) query = query.ilike('username', '%' + username + '%');

    var result = await query;

    res.json({
      logs: result.data || [],
      total: result.count || 0,
      limit: limit,
      offset: offset
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────── ADMIN ALL DEVICES ──────── */

router.get('/admin/devices', authenticate, requireAdmin, async function(_req, res) {
  try {
    var result = await supabase
      .from('devices')
      .select('id, user_id, name, ip, first_seen, last_seen, is_blocked, users(username)')
      .order('last_seen', { ascending: false });

    var all = [];
    var devices = result.data || [];
    for (var i = 0; i < devices.length; i++) {
      var d = devices[i];
      var uname = d.users ? d.users.username : 'unknown';
      all.push({
        deviceId: d.id,
        userId: d.user_id,
        username: uname,
        name: d.name,
        ip: d.ip,
        firstSeen: d.first_seen,
        lastSeen: d.last_seen,
        isBlocked: d.is_blocked
      });
    }

    res.json({ devices: all });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
