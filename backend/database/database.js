const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

/* ──────────── Connection ──────────── */
const connectDB = async () => {
  const conn = await mongoose.connect(process.env.MONGODB_URI);
  console.log(`MongoDB connected → ${conn.connection.host}`);
};

/* ──────────── User Schema ──────────── */
const DeviceSchema = new mongoose.Schema({
  name:      { type: String, default: 'Unknown' },
  ip:        { type: String, default: 'Unknown' },
  userAgent: { type: String, default: '' },
  firstSeen: { type: Date,   default: Date.now },
  lastSeen:  { type: Date,   default: Date.now },
  isBlocked: { type: Boolean, default: false }
}, { _id: true });

const UserSchema = new mongoose.Schema({
  username:            { type: String, required: true, unique: true, lowercase: true, trim: true, minlength: 3, maxlength: 30 },
  password:            { type: String, required: true, minlength: 8 },
  role:                { type: String, enum: ['user', 'admin'], default: 'user' },
  pageAccess:          [{ type: String, enum: ['home', 'about', 'workspace'] }],
  isBlocked:           { type: Boolean, default: false },
  blockedBy:           { type: String,  default: null },
  blockedAt:           { type: Date },
  blockedReason:       { type: String },
  failedLoginAttempts: { type: Number, default: 0 },
  lastFailedAttempt:   { type: Date },
  lastLogin:           { type: Date },
  lastLoginIP:         { type: String },
  lastLoginDevice:     { type: String },
  loginStatus:         { type: String, enum: ['active', 'inactive', 'blocked'], default: 'inactive' },
  devices:             [DeviceSchema]
}, { timestamps: true });

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

UserSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

const User = mongoose.model('User', UserSchema);

/* ──────────── Audit Log Schema ──────────── */
const AuditLogSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  username:  { type: String },
  action:    { type: String, required: true, enum: [
    'login', 'logout', 'page_view', 'login_failed',
    'blocked', 'unblocked', 'access_granted', 'access_revoked',
    'user_created', 'user_deleted', 'password_changed'
  ]},
  page:      { type: String },
  ip:        { type: String },
  device:    { type: String },
  userAgent: { type: String },
  status:    { type: String, enum: ['success', 'failure', 'blocked'], default: 'success' },
  details:   { type: String },
  timestamp: { type: Date, default: Date.now, index: true }
});

AuditLogSchema.index({ action: 1, timestamp: -1 });

const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

/* ──────────── Seed Admin ──────────── */
const seedAdmin = async () => {
  const uname = (process.env.ADMIN_SEED_USERNAME || 'admin').toLowerCase();
  const exists = await User.findOne({ username: uname });
  if (!exists) {
    await User.create({
      username:   uname,
      password:   process.env.ADMIN_SEED_PASSWORD || 'Admin123!',
      role:       'admin',
      pageAccess: ['home', 'about', 'workspace'],
      loginStatus:'active'
    });
    console.log(`✔ Admin user "${uname}" created`);
  }
};

module.exports = { connectDB, User, AuditLog, seedAdmin };
