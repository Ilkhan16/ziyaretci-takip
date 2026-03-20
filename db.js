const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || 'ziyaretci_takip';

let _client = null;

async function getDb() {
  if (_client) {
    try {
      await _client.db('admin').command({ ping: 1 });
    } catch {
      _client = null;
    }
  }
  if (!_client) {
    if (!MONGODB_URI) throw new Error('MONGODB_URI ortam degiskeni tanimlanmamis.');
    _client = new MongoClient(MONGODB_URI, { maxPoolSize: 10, serverSelectionTimeoutMS: 10000, connectTimeoutMS: 10000 });
    await _client.connect();
  }
  return _client.db(DB_NAME);
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

async function nextId(db, key) {
  const result = await db.collection('counters').findOneAndUpdate(
    { _id: key },
    { $inc: { seq: 1 } },
    { upsert: true, returnDocument: 'after' }
  );
  return result.seq;
}

// ── Admin Users ──────────────────────────────────────────────────

async function getAdminById(id) {
  const db = await getDb();
  return (await db.collection('admin_users').findOne({ id })) || null;
}

async function getAdminByEmail(email) {
  const db = await getDb();
  const norm = normalizeEmail(email);
  return (await db.collection('admin_users').findOne({ email: norm })) || null;
}

async function listAdmins() {
  const db = await getDb();
  return db.collection('admin_users').find({}).sort({ created_at: -1 }).toArray();
}

async function createAdmin({ email, password_hash, full_name, is_active, role, project_ids }) {
  const db = await getDb();
  const norm = normalizeEmail(email);
  const existing = await db.collection('admin_users').findOne({ email: norm });
  if (existing) {
    const err = new Error('UNIQUE: admin email');
    err.code = 'UNIQUE';
    throw err;
  }
  const id = await nextId(db, 'admin_users');
  const user = {
    id,
    email: norm,
    password_hash,
    full_name: full_name || null,
    is_active: is_active ? 1 : 0,
    role: role || 'admin',
    project_ids: Array.isArray(project_ids) ? project_ids : [],
    created_at: nowIso(),
  };
  await db.collection('admin_users').insertOne(user);
  return user;
}

async function updateAdmin(id, patch) {
  const db = await getDb();
  const user = await db.collection('admin_users').findOne({ id });
  if (!user) return null;

  const update = {};

  if (patch.email) {
    const norm = normalizeEmail(patch.email);
    const conflict = await db.collection('admin_users').findOne({ email: norm, id: { $ne: id } });
    if (conflict) {
      const err = new Error('UNIQUE: admin email');
      err.code = 'UNIQUE';
      throw err;
    }
    update.email = norm;
  }
  if (typeof patch.full_name !== 'undefined') update.full_name = patch.full_name || null;
  if (typeof patch.is_active !== 'undefined') update.is_active = patch.is_active ? 1 : 0;
  if (patch.password_hash) update.password_hash = patch.password_hash;
  if (typeof patch.role !== 'undefined') update.role = patch.role || 'admin';
  if (typeof patch.project_ids !== 'undefined') {
    update.project_ids = Array.isArray(patch.project_ids) ? patch.project_ids : [];
  }

  await db.collection('admin_users').updateOne({ id }, { $set: update });
  return { ...user, ...update };
}

// ── Projects ─────────────────────────────────────────────────────

async function getProjectBySlug(slug) {
  const db = await getDb();
  const s = String(slug || '').trim();
  return (await db.collection('projects').findOne({ slug: s })) || null;
}

async function getProjectById(id) {
  const db = await getDb();
  return (await db.collection('projects').findOne({ id })) || null;
}

async function listProjects({ activeOnly } = {}) {
  const db = await getDb();
  const filter = activeOnly ? { is_active: 1 } : {};
  return db.collection('projects').find(filter).sort({ created_at: -1 }).toArray();
}

async function saveProject(project) {
  const db = await getDb();
  const slug = String(project.slug || '').trim();
  if (!slug) throw new Error('Slug required');

  const slugConflict = await db.collection('projects').findOne(
    project.id ? { slug, id: { $ne: project.id } } : { slug }
  );
  if (slugConflict) {
    const err = new Error('UNIQUE: project slug');
    err.code = 'UNIQUE';
    throw err;
  }

  const existing = project.id ? await db.collection('projects').findOne({ id: project.id }) : null;

  const payload = {
    id: existing ? existing.id : await nextId(db, 'projects'),
    name: String(project.name || '').trim(),
    slug,
    is_active: project.is_active ? 1 : 0,
    isg_text_ziyaretci: String(project.isg_text_ziyaretci || ''),
    isg_text_tedarikci: String(project.isg_text_tedarikci || ''),
    isg_text_taseron: String(project.isg_text_taseron || ''),
    authorized_people: Array.isArray(project.authorized_people) ? project.authorized_people : [],
    email_recipients: Array.isArray(project.email_recipients) ? project.email_recipients : [],
    created_at: existing ? existing.created_at : nowIso(),
  };

  if (existing) {
    await db.collection('projects').replaceOne({ id: payload.id }, payload);
  } else {
    await db.collection('projects').insertOne(payload);
  }
  return payload;
}

// ── Entries ──────────────────────────────────────────────────────

async function createEntry(entry) {
  const db = await getDb();
  const id = await nextId(db, 'entries');
  const payload = {
    id,
    project_id: entry.project_id,
    entry_type: entry.entry_type,
    tc_kimlik_no: entry.tc_kimlik_no,
    full_name: entry.full_name,
    phone: entry.phone,
    visited_person: entry.visited_person,
    note: entry.note || null,
    isg_accepted: entry.isg_accepted ? 1 : 0,
    ip_address: entry.ip_address || null,
    created_at: nowIso(),
  };
  await db.collection('entries').insertOne(payload);
  return payload;
}

async function listEntries({ projectId, entryType, limit } = {}) {
  const db = await getDb();
  const filter = {};
  if (projectId) filter.project_id = projectId;
  if (entryType) filter.entry_type = entryType;
  let cursor = db.collection('entries').find(filter).sort({ created_at: -1 });
  if (limit && Number.isFinite(limit)) cursor = cursor.limit(limit);
  return cursor.toArray();
}

async function getEntryById(id) {
  const db = await getDb();
  return (await db.collection('entries').findOne({ id })) || null;
}

async function updateEntryExit(id) {
  const db = await getDb();
  const exit_at = nowIso();
  await db.collection('entries').updateOne({ id }, { $set: { exit_at } });
  return db.collection('entries').findOne({ id });
}

async function getLastEntryByTc(tc) {
  const db = await getDb();
  const entries = await db.collection('entries')
    .find({ tc_kimlik_no: tc })
    .sort({ created_at: -1 })
    .limit(1)
    .toArray();
  return entries.length > 0 ? entries[0] : null;
}

module.exports = {
  nowIso,
  getDb,
  // admins
  getAdminById,
  getAdminByEmail,
  listAdmins,
  createAdmin,
  updateAdmin,
  // projects
  getProjectBySlug,
  getProjectById,
  listProjects,
  saveProject,
  // entries
  createEntry,
  listEntries,
  getEntryById,
  updateEntryExit,
  getLastEntryByTc,
};
