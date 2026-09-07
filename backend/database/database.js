const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');

/* ─── Supabase Client ─── */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

/* ─── Health Check ─── */
const connectDB = async () => {
  const { data, error } = await supabase.from('users').select('id').limit(1);
  if (error && error.code !== 'PGRST116') {
    console.error('Supabase connection warning:', error.message);
  }
  console.log('Supabase connected');
};

/* ─── Seed Admin ─── */
const seedAdmin = async () => {
  const uname = (process.env.ADMIN_SEED_USERNAME || 'admin').toLowerCase();

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('username', uname)
    .single();

  if (!existing) {
    const hashed = await bcrypt.hash(process.env.ADMIN_SEED_PASSWORD || 'Admin123!', 12);
    const { error } = await supabase.from('users').insert({
      username:     uname,
      password:     hashed,
      role:         'admin',
      page_access:  ['home', 'about', 'workspace'],
      login_status: 'active'
    });
    if (error) {
      console.error('Admin seed error:', error.message);
    } else {
      console.log(`Admin user "${uname}" created`);
    }
  }
};

module.exports = { supabase, connectDB, seedAdmin };
