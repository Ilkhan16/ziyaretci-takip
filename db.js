const fs = require('fs');
const path = require('path');

const dataPath = path.join(__dirname, 'data.json');

function nowIso() {
  return new Date().toISOString();
}

function ensureDataShape(data) {
  const shaped = data && typeof data === 'object' ? data : {};
  if (!Array.isArray(shaped.admin_users)) shaped.admin_users = [];
  if (!Array.isArray(shaped.projects)) shaped.projects = [];
  if (!Array.isArray(shaped.entries)) shaped.entries = [];
  if (!shaped.counters || typeof shaped.counters !== 'object') shaped.counters = {};
  if (typeof shaped.counters.admin_users !== 'number') shaped.counters.admin_users = 0;
  if (typeof shaped.counters.projects !== 'number') shaped.counters.projects = 0;
  if (typeof shaped.counters.entries !== 'number') shaped.counters.entries = 0;
  return shaped;
}

function load() {
  if (!fs.existsSync(dataPath)) {
    return ensureDataShape(null);
  }
  const raw = fs.readFileSync(dataPath, 'utf8');
  if (!raw.trim()) return ensureDataShape(null);
  return ensureDataShape(JSON.parse(raw));
}

function save(data) {
  const shaped = ensureDataShape(data);
  const tmp = `${dataPath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(shaped, null, 2), 'utf8');
  fs.renameSync(tmp, dataPath);
}

function nextId(data, key) {
  data.counters[key] += 1;
  return data.counters[key];
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

// Admin Users
function getAdminById(id) {
  const data = load();
  return data.admin_users.find((u) => u.id === id) || null;
}

function getAdminByEmail(email) {
  const data = load();
  const norm = normalizeEmail(email);
  return data.admin_users.find((u) => normalizeEmail(u.email) === norm) || null;
}

function listAdmins() {
  const data = load();
  return [...data.admin_users].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

function createAdmin({ email, password_hash, full_name, is_active }) {
  const data = load();
  const norm = normalizeEmail(email);
  if (data.admin_users.some((u) => normalizeEmail(u.email) === norm)) {
    const err = new Error('UNIQUE: admin email');
    err.code = 'UNIQUE';
    throw err;
  }
  const user = {
    id: nextId(data, 'admin_users'),
    email: norm,
    password_hash,
    full_name: full_name || null,
    is_active: is_active ? 1 : 0,
    created_at: nowIso(),
  };
  data.admin_users.push(user);
  save(data);
  return user;
}

function updateAdmin(id, patch) {
  const data = load();
  const idx = data.admin_users.findIndex((u) => u.id === id);
  if (idx === -1) return null;

  if (patch.email) {
    const norm = normalizeEmail(patch.email);
    if (data.admin_users.some((u) => u.id !== id && normalizeEmail(u.email) === norm)) {
      const err = new Error('UNIQUE: admin email');
      err.code = 'UNIQUE';
      throw err;
    }
    data.admin_users[idx].email = norm;
  }

  if (typeof patch.full_name !== 'undefined') {
    data.admin_users[idx].full_name = patch.full_name || null;
  }
  if (typeof patch.is_active !== 'undefined') {
    data.admin_users[idx].is_active = patch.is_active ? 1 : 0;
  }
  if (patch.password_hash) {
    data.admin_users[idx].password_hash = patch.password_hash;
  }

  save(data);
  return data.admin_users[idx];
}

// Projects
function getProjectBySlug(slug) {
  const data = load();
  const s = String(slug || '').trim();
  return data.projects.find((p) => p.slug === s) || null;
}

function getProjectById(id) {
  const data = load();
  return data.projects.find((p) => p.id === id) || null;
}

function listProjects({ activeOnly } = {}) {
  const data = load();
  const items = activeOnly ? data.projects.filter((p) => p.is_active === 1) : data.projects;
  return [...items].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

function saveProject(project) {
  const data = load();
  const slug = String(project.slug || '').trim();
  if (!slug) throw new Error('Slug required');

  const existingIdx = project.id ? data.projects.findIndex((p) => p.id === project.id) : -1;
  const slugTaken = data.projects.some((p) => p.slug === slug && (existingIdx === -1 || p.id !== project.id));
  if (slugTaken) {
    const err = new Error('UNIQUE: project slug');
    err.code = 'UNIQUE';
    throw err;
  }

  const payload = {
    id: existingIdx === -1 ? nextId(data, 'projects') : data.projects[existingIdx].id,
    name: String(project.name || '').trim(),
    slug,
    is_active: project.is_active ? 1 : 0,
    isg_text_ziyaretci: String(project.isg_text_ziyaretci || ''),
    isg_text_tedarikci: String(project.isg_text_tedarikci || ''),
    isg_text_taseron: String(project.isg_text_taseron || ''),
    authorized_people: Array.isArray(project.authorized_people) ? project.authorized_people : [],
    email_recipients: Array.isArray(project.email_recipients) ? project.email_recipients : [],
    created_at: existingIdx === -1 ? nowIso() : data.projects[existingIdx].created_at,
  };

  if (existingIdx === -1) data.projects.push(payload);
  else data.projects[existingIdx] = payload;

  save(data);
  return payload;
}

// Entries
function createEntry(entry) {
  const data = load();
  const payload = {
    id: nextId(data, 'entries'),
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
  data.entries.push(payload);
  save(data);
  return payload;
}

function listEntries({ projectId, entryType, limit } = {}) {
  const data = load();
  let items = data.entries;
  if (projectId) items = items.filter((e) => e.project_id === projectId);
  if (entryType) items = items.filter((e) => e.entry_type === entryType);
  items = [...items].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  if (limit && Number.isFinite(limit)) items = items.slice(0, limit);
  return items;
}

function getLastEntryByTc(tc) {
  const data = load();
  const matches = data.entries
    .filter((e) => e.tc_kimlik_no === tc)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return matches.length > 0 ? matches[0] : null;
}

module.exports = {
  nowIso,
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
  getLastEntryByTc,
};
