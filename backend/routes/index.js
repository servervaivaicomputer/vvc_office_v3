const express = require('express');
const router  = express.Router();
const path    = require('path');
const fs      = require('fs');
const { handleAuthCallback, authenticate, checkPageAccess, logActivity } = require('../middleware/auth');
const FRONTEND = process.env.FRONTEND_URL;

/* Apply the auth-callback handler (consumes ?auth= token → cookie) to ALL page routes first */
router.use(handleAuthCallback);

/* Helper: serve a protected HTML file from projects/ */
const serve = (page) => async (req, res) => {
  const fp = path.join(__dirname, '..', 'projects', page, 'index.html');
  if (!fs.existsSync(fp)) return res.status(404).send('Not found');
  let html = fs.readFileSync(fp, 'utf8');
  html = html.replace(/\{\{USERNAME\}\}/g,    req.user.username)
             .replace(/\{\{ROLE\}\}/g,         req.user.role)
             .replace(/\{\{USER_PAGES\}\}/g,   JSON.stringify(req.user.pageAccess))
             .replace(/\{\{FRONTEND_URL\}\}/g, FRONTEND);
  await logActivity({ userId: req.user._id, username: req.user.username, action: 'page_view', page, ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
};

/* Home */
router.get('/',                authenticate, checkPageAccess('home'), serve('home'));
router.get('/projects/home',   authenticate, checkPageAccess('home'), serve('home'));

/* About */
router.get('/projects/about',  authenticate, checkPageAccess('about'), serve('about'));

/* Workspace */
router.get('/projects/workspace', authenticate, checkPageAccess('workspace'), serve('workspace'));

/* Admin panel */
router.get('/admin', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only.');
  const fp = path.join(__dirname, '..', 'admin', 'index.html');
  if (!fs.existsSync(fp)) return res.status(404).send('Not found');
  let html = fs.readFileSync(fp, 'utf8');
  html = html.replace(/\{\{USERNAME\}\}/g, req.user.username)
             .replace(/\{\{FRONTEND_URL\}\}/g, FRONTEND);
  await logActivity({ userId: req.user._id, username: req.user.username, action: 'page_view', page: 'admin', ip: req.clientIP, device: req.deviceInfo.name, userAgent: req.deviceInfo.ua, status: 'success' });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

module.exports = router;
