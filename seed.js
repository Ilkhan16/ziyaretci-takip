require('dotenv').config();

const bcrypt = require('bcryptjs');
const { getAdminByEmail, createAdmin } = require('./db');

const adminEmail = (process.env.SEED_ADMIN_EMAIL || '').trim().toLowerCase();
const adminPassword = process.env.SEED_ADMIN_PASSWORD || '';

if (!adminEmail || !adminPassword) {
  // eslint-disable-next-line no-console
  console.error('SEED_ADMIN_EMAIL ve SEED_ADMIN_PASSWORD .env içinde tanımlı olmalı.');
  process.exit(1);
}

const existing = getAdminByEmail(adminEmail);
if (existing) {
  // eslint-disable-next-line no-console
  console.log('Admin kullanıcı zaten var.');
  process.exit(0);
}

const hash = bcrypt.hashSync(adminPassword, 10);
createAdmin({
  email: adminEmail,
  password_hash: hash,
  full_name: process.env.SEED_ADMIN_FULL_NAME || 'Admin',
  is_active: true,
});

// eslint-disable-next-line no-console
console.log('Admin kullanıcı oluşturuldu:', adminEmail);
