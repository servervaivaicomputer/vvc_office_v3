require('dotenv').config();

const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const cookieParser  = require('cookie-parser');
const rateLimit     = require('express-rate-limit');
const jwt           = require('jsonwebtoken');
const fs            = require('fs');
const path          = require('path');
const { connectDB, seedAdmin } = require('./database/database');
const { COOKIE_NAME } = require('./middleware/auth');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ── Security headers ── */
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

/* ── CORS ── */
app.use(cors({
  origin:      true,
  credentials: true,
  methods:     ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

/* ── Body parsers ── */
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

/* ── HPP ── */
const hpp = require('hpp');
app.use(hpp());

/* ── Global rate limit ── */
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      300,
  standardHeaders: true,
  legacyHeaders:   false
}));

app.disable('x-powered-by');

/* ── API Routes ── */
app.use('/api', require('./routes/api'));
app.use('/',    require('./routes/index'));

/* ── Admin Panel at /admin ── */
app.get('/admin', async function(req, res) {
  try {
    var token = req.cookies[COOKIE_NAME] || '';
    if (!token && req.headers.authorization) {
      token = req.headers.authorization.replace('Bearer ', '');
    }
    if (!token) {
      return res.redirect('/login');
    }

    var decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.redirect('/login');
    }

    var fp = path.join(__dirname, 'admin', 'index.html');
    if (!fs.existsSync(fp)) {
      return res.status(404).send('Admin panel not found');
    }

    var html = fs.readFileSync(fp, 'utf8');
    var backendUrl = req.protocol + '://' + req.get('host');

    html = html.replace(/\{\{USERNAME\}\}/g, decoded.username || '');
    html = html.replace(/\{\{FRONTEND_URL\}\}/g, process.env.FRONTEND_URL || '');
    html = html.replace(/\{\{BACKEND_URL\}\}/g, backendUrl);
    html = html.replace(/\{\{AUTH_TOKEN\}\}/g, token);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    return res.redirect('/login');
  }
});

/* ── Health ── */
app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

/* ── 404 + Error ── */
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

/* ── Start ── */
(async () => {
  await connectDB();
  await seedAdmin();
  app.listen(PORT, () => console.log('Server on :' + PORT + ' [' + process.env.NODE_ENV + ']'));
})().catch(function(e) {
  console.error('Startup failed:', e);
  process.exit(1);
});
