require('dotenv').config();

const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const cookieParser  = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const hpp           = require('hpp');
const rateLimit     = require('express-rate-limit');
const { connectDB, seedAdmin } = require('./database/database');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ── Security headers ── */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
      styleSrc:   ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
      fontSrc:    ["'self'", "fonts.gstatic.com", "fonts.googleapis.com"],
      imgSrc:     ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

/* ── CORS — frontend domain allow + credentials ── */
app.use(cors({
  origin:      process.env.FRONTEND_URL || 'https://your-site.netlify.app',
  credentials: true,
  methods:     ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

/* ── Body parsers ── */
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

/* ── NoSQL injection & HPP ── */
app.use(mongoSanitize());
app.use(hpp());

/* ── Global rate limit ── */
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      300,
  standardHeaders: true,
  legacyHeaders:   false
}));

/* ── Disable fingerprinting ── */
app.disable('x-powered-by');

/* ── Routes ── */
app.use('/api', require('./routes/api'));
app.use('/',    require('./routes/index'));

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
  app.listen(PORT, () => console.log(`Server listening on :${PORT} [${process.env.NODE_ENV}]`));
})().catch(e => {
  console.error('Startup failed:', e);
  process.exit(1);
});
