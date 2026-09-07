require('dotenv').config();

const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const cookieParser  = require('cookie-parser');
const rateLimit     = require('express-rate-limit');
const { connectDB, seedAdmin } = require('./database/database');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ── Security headers ── */
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

/* ── CORS — সব URL allow ── */
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
  app.listen(PORT, () => console.log(`Server on :${PORT} [${process.env.NODE_ENV}]`));
})().catch(e => {
  console.error('Startup failed:', e);
  process.exit(1);
});
