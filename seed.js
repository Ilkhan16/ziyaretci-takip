require('dotenv').config();

const bcrypt = require('bcryptjs');
const { getAdminByEmail, createAdmin } = require('./db');

async function main() {
  const adminEmail = (process.env.SEED_ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || '';

  if (!adminEmail || !adminPassword) {
    console.error('SEED_ADMIN_EMAIL ve SEED_ADMIN_PASSWORD .env içinde tanımlı olmalı.');
    process.exit(1);
  }

  const existing = await getAdminByEmail(adminEmail);
  if (existing) {
    console.log('Admin kullanıcı zaten var:', adminEmail);
    process.exit(0);
  }

  const hash = bcrypt.hashSync(adminPassword, 10);
  await createAdmin({
    email: adminEmail,
    password_hash: hash,
    full_name: process.env.SEED_ADMIN_FULL_NAME || 'Admin',
    is_active: true,
    role: 'admin',
    project_ids: [],
  });

  console.log('Admin kullanıcı oluşturuldu:', adminEmail);
  process.exit(0);
}

main().catch((err) => {
  console.error('Seed hatası:', err);
  process.exit(1);
});
