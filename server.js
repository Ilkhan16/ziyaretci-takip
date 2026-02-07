require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');

const {
  getAdminById,
  getAdminByEmail,
  listAdmins,
  createAdmin,
  updateAdmin,
  getProjectBySlug,
  getProjectById,
  listProjects,
  saveProject,
  createEntry,
  listEntries,
  getEntryById,
  updateEntryExit,
  getLastEntryByTc,
} = require('./db');

const app = express();

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
let BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
if (!/^https?:\/\//i.test(BASE_URL)) BASE_URL = 'https://' + BASE_URL;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    store: new MemoryStore({ checkPeriod: 86400000 }),
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

app.use('/public', express.static(path.join(__dirname, 'public')));

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.adminUserId) {
    return res.redirect('/admin/login');
  }
  const admin = getAdminById(req.session.adminUserId);
  if (!admin || admin.is_active !== 1) {
    req.session.adminUserId = null;
    return res.redirect('/admin/login');
  }
  req.admin = {
    id: admin.id,
    email: admin.email,
    full_name: admin.full_name,
    is_active: admin.is_active,
    role: admin.role || 'admin',
    project_ids: Array.isArray(admin.project_ids) ? admin.project_ids : [],
  };
  next();
}

function requireSuperAdmin(req, res, next) {
  if (req.admin.role !== 'admin') {
    return res.status(403).send('Yetkiniz yok.');
  }
  next();
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || null;
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

// ── Rate limiter (IP bazlı, memory) ──────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 10 * 60 * 1000; // 10 dakika
const RATE_LIMIT_MAX = 5; // pencere başına max form gönderimi

function rateLimit(req, res, next) {
  const ip = getClientIp(req) || 'unknown';
  const now = Date.now();
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = rateLimitMap.get(ip).filter((t) => now - t < RATE_LIMIT_WINDOW);
  rateLimitMap.set(ip, timestamps);
  if (timestamps.length >= RATE_LIMIT_MAX) {
    return res.status(429).render('public_error', {
      title: 'Çok fazla istek',
      message: 'Çok fazla form gönderimi yaptınız. Lütfen 10 dakika sonra tekrar deneyin.',
    });
  }
  timestamps.push(now);
  next();
}

// Eski rate limit kayıtlarını temizle (her 15dk)
setInterval(() => {
  const now = Date.now();
  for (const [ip, ts] of rateLimitMap) {
    const valid = ts.filter((t) => now - t < RATE_LIMIT_WINDOW);
    if (valid.length === 0) rateLimitMap.delete(ip);
    else rateLimitMap.set(ip, valid);
  }
}, 15 * 60 * 1000);

// ── Mail gönderimi ───────────────────────────────────────────────
let mailTransporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  mailTransporter.verify().then(() => {
    console.log('✓ Mail bağlantısı başarılı');
  }).catch((err) => {
    console.error('✗ Mail bağlantı hatası:', err.message);
  });
} else {
  console.log('ℹ SMTP ayarları yapılmamış, mail gönderimi devre dışı');
}

function sendEntryNotification(project, entry) {
  if (!mailTransporter) return;
  const recipients = safeArray(project.email_recipients).filter((e) => e && e.includes('@'));
  if (!recipients.length) return;

  const subject = `[${project.name}] Yeni Ziyaretçi Girişi - ${entry.full_name}`;
  const html = `
    <div style="font-family:sans-serif;max-width:500px;margin:0 auto;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
      <div style="background:#6366f1;color:#fff;padding:16px 20px;">
        <h2 style="margin:0;font-size:18px;">${project.name}</h2>
        <p style="margin:4px 0 0;opacity:0.9;font-size:13px;">Yeni ziyaretçi girişi kaydedildi</p>
      </div>
      <div style="padding:20px;">
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="padding:8px 0;color:#64748b;width:120px;">Ad Soyad</td><td style="padding:8px 0;font-weight:600;">${entry.full_name}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Giriş Türü</td><td style="padding:8px 0;">${entry.entry_type}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Telefon</td><td style="padding:8px 0;">${entry.phone}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Ziyaret Edilen</td><td style="padding:8px 0;">${entry.visited_person}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Tarih</td><td style="padding:8px 0;">${new Date(entry.created_at).toLocaleString('tr-TR')}</td></tr>
        </table>
      </div>
      <div style="background:#f8fafc;padding:12px 20px;font-size:12px;color:#94a3b8;text-align:center;">
        Bu e-posta otomatik olarak gönderilmiştir.
      </div>
    </div>
  `;

  mailTransporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: recipients.join(', '),
    subject,
    html,
  }).catch((err) => {
    console.error('Mail gönderilemedi:', err.message);
  });
}

app.get('/', (req, res) => {
  res.redirect('/admin');
});

// TC lookup API — returns last entry info for auto-fill
app.get('/api/tc-lookup/:tc', (req, res) => {
  const tc = (req.params.tc || '').trim();
  if (!/^[0-9]{11}$/.test(tc)) return res.json({ found: false });
  const entry = getLastEntryByTc(tc);
  if (!entry) return res.json({ found: false });
  res.json({
    found: true,
    full_name: entry.full_name,
    phone: entry.phone,
    entry_type: entry.entry_type,
  });
});

// Public form (project specific)
app.get('/p/:slug', (req, res) => {
  const project = getProjectBySlug(req.params.slug);
  if (!project || project.is_active !== 1) {
    return res.status(404).render('public_not_found', { title: 'Proje bulunamadı' });
  }

  const authorizedPeople = safeArray(project.authorized_people);
  const entryTypes = ['Ziyaretçi', 'Tedarikçi', 'Taşeron'];

  res.render('public_form', {
    title: `${project.name} - Giriş Formu`,
    project,
    entryTypes,
    authorizedPeople,
    errors: [],
    values: {
      entry_type: '',
      tc_kimlik_no: '',
      full_name: '',
      phone: '',
      visited_person: '',
      note: '',
      isg_accepted: false,
    },
  });
});

app.post('/p/:slug', rateLimit, (req, res) => {
  const project = getProjectBySlug(req.params.slug);
  if (!project || project.is_active !== 1) {
    return res.status(404).render('public_not_found', { title: 'Proje bulunamadı' });
  }

  // Honeypot — botlar bu gizli alanı doldurur, gerçek kullanıcılar doldurmaz
  if (req.body._website && req.body._website.trim().length > 0) {
    return res.render('public_success', { title: 'Kayıt alındı', project, entry: { full_name: 'Kayıt', created_at: new Date().toISOString() } });
  }

  // Zamanlama kontrolü — form 3 saniyeden kısa sürede doldurulamaz
  const formTime = parseInt(req.body._ft || '0', 10);
  if (formTime && (Date.now() - formTime) < 3000) {
    return res.status(429).render('public_error', {
      title: 'Çok hızlı',
      message: 'Formu çok hızlı doldurdunuz. Lütfen tekrar deneyin.',
    });
  }

  const authorizedPeople = safeArray(project.authorized_people);
  const entryTypes = ['Ziyaretçi', 'Tedarikçi', 'Taşeron'];

  const values = {
    entry_type: (req.body.entry_type || '').trim(),
    tc_kimlik_no: (req.body.tc_kimlik_no || '').trim(),
    full_name: (req.body.full_name || '').trim(),
    phone: (req.body.phone || '').trim(),
    visited_person: (req.body.visited_person || '').trim(),
    note: (req.body.note || '').trim(),
    isg_accepted: req.body.isg_accepted === 'on',
  };

  const errors = [];
  if (!entryTypes.includes(values.entry_type)) errors.push('Giriş Türü seçiniz.');
  if (!/^[0-9]{11}$/.test(values.tc_kimlik_no)) errors.push('TC Kimlik Numarası 11 haneli olmalıdır.');
  if (values.full_name.length < 3) errors.push('Ad Soyad zorunludur.');
  if (values.phone.length < 10) errors.push('Cep Telefonu zorunludur.');
  if (values.visited_person.length < 2) errors.push('Ziyaret edilen kişi seçilmelidir.');
  if (!values.isg_accepted) errors.push('İSG kurallarını okuduğunuzu ve kabul ettiğinizi onaylamalısınız.');

  if (errors.length > 0) {
    return res.status(400).render('public_form', {
      title: `${project.name} - Giriş Formu`,
      project,
      entryTypes,
      authorizedPeople,
      errors,
      values,
    });
  }

  const ip = getClientIp(req);

  const entry = createEntry({
    project_id: project.id,
    entry_type: values.entry_type,
    tc_kimlik_no: values.tc_kimlik_no,
    full_name: values.full_name,
    phone: values.phone,
    visited_person: values.visited_person,
    note: values.note || null,
    isg_accepted: true,
    ip_address: ip,
  });

  // Mail bildirimi gönder
  sendEntryNotification(project, entry);

  res.render('public_success', {
    title: 'Kayıt alındı',
    project,
    entry,
  });
});

// QR page & QR PNG for project
app.get('/p/:slug/qr', async (req, res) => {
  const project = getProjectBySlug(req.params.slug);
  if (!project || project.is_active !== 1) {
    return res.status(404).render('public_not_found', { title: 'Proje bulunamadı' });
  }
  const formUrl = `${BASE_URL}/p/${project.slug}`;
  res.render('public_qr', {
    title: `${project.name} - QR`,
    project,
    formUrl,
  });
});

app.get('/p/:slug/qr.png', async (req, res) => {
  const project = getProjectBySlug(req.params.slug);
  if (!project || project.is_active !== 1) {
    return res.status(404).end();
  }
  const formUrl = `${BASE_URL}/p/${project.slug}`;

  try {
    const pngBuffer = await QRCode.toBuffer(formUrl, {
      type: 'png',
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 512,
    });
    res.setHeader('Content-Type', 'image/png');
    res.send(pngBuffer);
  } catch {
    res.status(500).end();
  }
});

// Admin
app.get('/admin', requireAdmin, (req, res) => {
  res.redirect('/admin/dashboard');
});

// Dashboard
app.get('/admin/dashboard', requireAdmin, (req, res) => {
  let allProjects = listProjects({ activeOnly: false });
  if (req.admin.role === 'customer') {
    allProjects = allProjects.filter((p) => req.admin.project_ids.includes(p.id));
  }

  const allEntries = listEntries({ limit: 50000 });
  let entries = req.admin.role === 'customer'
    ? allEntries.filter((e) => req.admin.project_ids.includes(e.project_id))
    : allEntries;

  const now = new Date();
  const todayStr = now.toISOString().slice(0, 10);

  const todayEntries = entries.filter((e) => e.created_at && e.created_at.slice(0, 10) === todayStr);
  const activeNow = entries.filter((e) => !e.exit_at);

  // Son 7 gun verileri
  const last7 = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const ds = d.toISOString().slice(0, 10);
    const dayLabel = d.toLocaleDateString('tr-TR', { weekday: 'short', day: 'numeric', month: 'short' });
    const count = entries.filter((e) => e.created_at && e.created_at.slice(0, 10) === ds).length;
    last7.push({ date: ds, label: dayLabel, count });
  }

  // Tur dagilimi
  const typeCounts = { Ziyaretci: 0, Tedarikci: 0, Taseron: 0 };
  entries.forEach((e) => {
    if (e.entry_type === 'Ziyaret\u00e7i') typeCounts.Ziyaretci++;
    else if (e.entry_type === 'Tedarik\u00e7i') typeCounts.Tedarikci++;
    else if (e.entry_type === 'Ta\u015feron') typeCounts.Taseron++;
  });

  // Son 5 kayit
  const recentEntries = entries.slice(0, 5);
  const projectMap = new Map(allProjects.map((p) => [p.id, p]));
  recentEntries.forEach((e) => {
    const p = projectMap.get(e.project_id);
    e.project_name = p ? p.name : '';
  });

  res.render('admin_dashboard', {
    title: 'Dashboard',
    admin: req.admin,
    totalEntries: entries.length,
    todayCount: todayEntries.length,
    activeCount: activeNow.length,
    projectCount: allProjects.length,
    last7: JSON.stringify(last7),
    typeCounts: JSON.stringify(typeCounts),
    recentEntries,
  });
});

app.get('/admin/login', (req, res) => {
  res.render('admin_login', {
    title: 'Admin Giriş',
    error: null,
    values: { email: '' },
  });
});

app.post('/admin/login', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';

  const user = getAdminByEmail(email);

  if (!user || user.is_active !== 1 || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).render('admin_login', {
      title: 'Admin Giriş',
      error: 'E-posta veya şifre hatalı.',
      values: { email },
    });
  }

  req.session.adminUserId = user.id;
  res.redirect('/admin');
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  req.session.adminUserId = null;
  res.redirect('/admin/login');
});

app.get('/admin/entries', requireAdmin, (req, res) => {
  let projects = listProjects({ activeOnly: false }).sort((a, b) => a.name.localeCompare(b.name));

  if (req.admin.role === 'customer') {
    projects = projects.filter((p) => req.admin.project_ids.includes(p.id));
  }

  const projectId = req.query.project_id ? Number(req.query.project_id) : null;
  const entryType = req.query.entry_type ? String(req.query.entry_type) : '';
  const durum = req.query.durum || '';

  const normalizedProjectId = projectId && Number.isFinite(projectId) ? projectId : null;
  const normalizedEntryType = entryType && ['Ziyaretçi', 'Tedarikçi', 'Taşeron'].includes(entryType) ? entryType : '';

  if (req.admin.role === 'customer' && normalizedProjectId && !req.admin.project_ids.includes(normalizedProjectId)) {
    return res.status(403).send('Bu projeye erişim yetkiniz yok.');
  }

  const rawEntries = listEntries({
    projectId: normalizedProjectId || undefined,
    entryType: normalizedEntryType || undefined,
    limit: 2000,
  });

  const projectMap = new Map(projects.map((p) => [p.id, p]));
  let entries = rawEntries.map((e) => {
    const p = projectMap.get(e.project_id) || null;
    return { ...e, project_name: p ? p.name : '', project_slug: p ? p.slug : '' };
  });

  if (req.admin.role === 'customer') {
    entries = entries.filter((e) => req.admin.project_ids.includes(e.project_id));
  }

  // Durum filtresi: icerde / cikti
  if (durum === 'icerde') {
    entries = entries.filter((e) => !e.exit_at);
  } else if (durum === 'cikti') {
    entries = entries.filter((e) => !!e.exit_at);
  }

  res.render('admin_entries', {
    title: 'Kayıtlar',
    admin: req.admin,
    projects,
    entries,
    filters: {
      project_id: projectId || '',
      entry_type: entryType || '',
      durum: durum || '',
    },
  });
});

// Bulk exit — mark all active visitors as left
app.post('/admin/entries/bulk-exit', requireAdmin, (req, res) => {
  const allEntries = listEntries({ limit: 50000 });
  let active = allEntries.filter((e) => !e.exit_at);
  if (req.admin.role === 'customer') {
    active = active.filter((e) => req.admin.project_ids.includes(e.project_id));
  }
  active.forEach((e) => updateEntryExit(e.id));
  res.redirect('/admin/entries?durum=icerde');
});

// Entry exit — mark visitor as left
app.post('/admin/entries/:id/exit', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const entry = getEntryById(id);
  if (!entry) return res.status(404).send('Kayit bulunamadi.');
  if (req.admin.role === 'customer' && !req.admin.project_ids.includes(entry.project_id)) {
    return res.status(403).send('Yetkiniz yok.');
  }
  if (!entry.exit_at) {
    updateEntryExit(id);
  }
  res.redirect('/admin/entries' + (req.body.redirect_query || ''));
});

// Visitor card print page
app.get('/admin/entries/:id/print', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const entry = getEntryById(id);
  if (!entry) return res.status(404).send('Kayit bulunamadi.');

  // Customer yetki kontrolu
  if (req.admin.role === 'customer' && !req.admin.project_ids.includes(entry.project_id)) {
    return res.status(403).send('Bu kayda erisim yetkiniz yok.');
  }

  const project = getProjectById(entry.project_id);
  res.render('print_visitor_card', {
    title: 'Ziyaretci Karti',
    entry,
    project,
  });
});

// Excel CSV export
app.get('/admin/entries/export', requireAdmin, (req, res) => {
  let projects = listProjects({ activeOnly: false });
  if (req.admin.role === 'customer') {
    projects = projects.filter((p) => req.admin.project_ids.includes(p.id));
  }

  const projectId = req.query.project_id ? Number(req.query.project_id) : null;
  const entryType = req.query.entry_type ? String(req.query.entry_type) : '';

  if (req.admin.role === 'customer' && projectId && !req.admin.project_ids.includes(projectId)) {
    return res.status(403).send('Yetkiniz yok.');
  }

  let rawEntries = listEntries({
    projectId: projectId || undefined,
    entryType: entryType || undefined,
    limit: 10000,
  });

  if (req.admin.role === 'customer') {
    rawEntries = rawEntries.filter((e) => req.admin.project_ids.includes(e.project_id));
  }

  const projectMap = new Map(projects.map((p) => [p.id, p]));

  // BOM for Excel UTF-8
  let csv = '\uFEFF';
  csv += 'Proje;Giris Turu;TC Kimlik;Ad Soyad;Telefon;Ziyaret Edilen;Not;Tarih\n';
  rawEntries.forEach((e) => {
    const p = projectMap.get(e.project_id);
    const pName = p ? p.name : '';
    const date = e.created_at ? new Date(e.created_at).toLocaleString('tr-TR') : '';
    csv += `"${pName}";"${e.entry_type}";"${e.tc_kimlik_no}";"${e.full_name}";"${e.phone}";"${e.visited_person}";"${(e.note || '').replace(/"/g, '""')}";"${date}"\n`;
  });

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=kayitlar.csv');
  res.send(csv);
});

app.get('/admin/projects', requireAdmin, requireSuperAdmin, (req, res) => {
  const projects = listProjects();
  res.render('admin_projects', {
    title: 'Projeler',
    admin: req.admin,
    projects,
  });
});

app.get('/admin/projects/new', requireAdmin, requireSuperAdmin, (req, res) => {
  res.render('admin_project_edit', {
    title: 'Proje Ekle',
    admin: req.admin,
    error: null,
    project: null,
    values: {
      name: '',
      slug: '',
      is_active: true,
      isg_text_ziyaretci: '',
      isg_text_tedarikci: '',
      isg_text_taseron: '',
      authorized_people_lines: '',
      email_recipients_lines: '',
    },
  });
});

app.get('/admin/projects/:id', requireAdmin, requireSuperAdmin, (req, res) => {
  const id = Number(req.params.id);
  const project = getProjectById(id);
  if (!project) return res.status(404).send('Not found');

  const authorizedPeople = safeArray(project.authorized_people);
  const emailRecipients = safeArray(project.email_recipients);

  res.render('admin_project_edit', {
    title: 'Proje Düzenle',
    admin: req.admin,
    error: null,
    project,
    values: {
      name: project.name,
      slug: project.slug,
      is_active: project.is_active === 1,
      isg_text_ziyaretci: project.isg_text_ziyaretci,
      isg_text_tedarikci: project.isg_text_tedarikci,
      isg_text_taseron: project.isg_text_taseron,
      authorized_people_lines: authorizedPeople.join('\n'),
      email_recipients_lines: emailRecipients.join('\n'),
    },
  });
});

app.post('/admin/projects/save', requireAdmin, requireSuperAdmin, (req, res) => {
  const id = req.body.id ? Number(req.body.id) : null;

  const values = {
    name: (req.body.name || '').trim(),
    slug: (req.body.slug || '').trim(),
    is_active: req.body.is_active === 'on',
    isg_text_ziyaretci: (req.body.isg_text_ziyaretci || '').trim(),
    isg_text_tedarikci: (req.body.isg_text_tedarikci || '').trim(),
    isg_text_taseron: (req.body.isg_text_taseron || '').trim(),
    authorized_people_lines: (req.body.authorized_people_lines || '').trim(),
    email_recipients_lines: (req.body.email_recipients_lines || '').trim(),
  };

  const error =
    !values.name
      ? 'Proje adı zorunludur.'
      : !/^[a-z0-9\-]{3,50}$/i.test(values.slug)
        ? 'Slug sadece harf/rakam/tire içermeli ve 3-50 karakter olmalıdır.'
        : !values.isg_text_ziyaretci || !values.isg_text_tedarikci || !values.isg_text_taseron
          ? 'Tüm İSG metinleri zorunludur.'
          : null;

  if (error) {
    return res.status(400).render('admin_project_edit', {
      title: id ? 'Proje Düzenle' : 'Proje Ekle',
      admin: req.admin,
      error,
      project: id ? { id } : null,
      values,
    });
  }

  const authorizedPeople = values.authorized_people_lines
    ? values.authorized_people_lines
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  const emailRecipients = values.email_recipients_lines
    ? values.email_recipients_lines
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  try {
    saveProject({
      id: id || undefined,
      name: values.name,
      slug: values.slug,
      is_active: values.is_active,
      isg_text_ziyaretci: values.isg_text_ziyaretci,
      isg_text_tedarikci: values.isg_text_tedarikci,
      isg_text_taseron: values.isg_text_taseron,
      authorized_people: authorizedPeople,
      email_recipients: emailRecipients,
    });
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    return res.status(400).render('admin_project_edit', {
      title: id ? 'Proje Düzenle' : 'Proje Ekle',
      admin: req.admin,
      error: msg.includes('UNIQUE') ? 'Slug zaten kullanılıyor.' : 'Kaydedilemedi.',
      project: id ? { id } : null,
      values,
    });
  }

  res.redirect('/admin/projects');
});

app.get('/admin/users', requireAdmin, (req, res) => {
  let users = listAdmins().map((u) => ({
    id: u.id,
    email: u.email,
    full_name: u.full_name,
    is_active: u.is_active,
    role: u.role || 'admin',
    project_ids: Array.isArray(u.project_ids) ? u.project_ids : [],
    created_at: u.created_at,
  }));
  // Customer sadece kendi projeleriyle kesisen customer kullanicilari gorsun
  if (req.admin.role === 'customer') {
    users = users.filter((u) => u.role === 'customer' && u.project_ids.some((pid) => req.admin.project_ids.includes(pid)));
  }
  res.render('admin_users', {
    title: 'Kullanicilar',
    admin: req.admin,
    users,
  });
});

app.get('/admin/users/new', requireAdmin, (req, res) => {
  let allProjects = listProjects();
  let defaultRole = 'admin';
  if (req.admin.role === 'customer') {
    allProjects = allProjects.filter((p) => req.admin.project_ids.includes(p.id));
    defaultRole = 'customer';
  }
  res.render('admin_user_edit', {
    title: 'Kullanici Ekle',
    admin: req.admin,
    error: null,
    user: null,
    allProjects,
    values: { email: '', full_name: '', password: '', is_active: true, role: defaultRole, project_ids: [] },
  });
});

app.get('/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = getAdminById(id);
  if (!user) return res.status(404).send('Not found');
  // Customer baska admin'i duzenleyemez, sadece kendi projelerindeki customer'lari
  if (req.admin.role === 'customer') {
    const uPids = Array.isArray(user.project_ids) ? user.project_ids : [];
    if ((user.role || 'admin') !== 'customer' || !uPids.some((pid) => req.admin.project_ids.includes(pid))) {
      return res.status(403).send('Bu kullaniciyi duzenleme yetkiniz yok.');
    }
  }
  let allProjects = listProjects();
  if (req.admin.role === 'customer') {
    allProjects = allProjects.filter((p) => req.admin.project_ids.includes(p.id));
  }
  res.render('admin_user_edit', {
    title: 'Kullanici Duzenle',
    admin: req.admin,
    error: null,
    user,
    allProjects,
    values: {
      email: user.email,
      full_name: user.full_name || '',
      password: '',
      is_active: user.is_active === 1,
      role: user.role || 'admin',
      project_ids: Array.isArray(user.project_ids) ? user.project_ids : [],
    },
  });
});

app.post('/admin/users/save', requireAdmin, (req, res) => {
  const id = req.body.id ? Number(req.body.id) : null;

  const values = {
    email: (req.body.email || '').trim().toLowerCase(),
    full_name: (req.body.full_name || '').trim(),
    password: req.body.password || '',
    is_active: req.body.is_active === 'on',
    role: (req.body.role || 'admin').trim(),
    project_ids: req.body.project_ids
      ? (Array.isArray(req.body.project_ids) ? req.body.project_ids : [req.body.project_ids]).map(Number).filter(Number.isFinite)
      : [],
  };

  // Customer kisitlamalari
  if (req.admin.role === 'customer') {
    values.role = 'customer'; // customer sadece customer olusturabilir
    values.project_ids = values.project_ids.filter((pid) => req.admin.project_ids.includes(pid));
  }

  const error =
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(values.email)
      ? 'Geçerli bir e-posta giriniz.'
      : !id && values.password.length < 6
        ? 'Şifre en az 6 karakter olmalıdır.'
        : null;

  if (error) {
    let allProjects = listProjects();
    if (req.admin.role === 'customer') {
      allProjects = allProjects.filter((p) => req.admin.project_ids.includes(p.id));
    }
    return res.status(400).render('admin_user_edit', {
      title: id ? 'Kullanici Duzenle' : 'Kullanici Ekle',
      admin: req.admin,
      error,
      user: id ? { id } : null,
      allProjects,
      values,
    });
  }

  try {
    if (id) {
      // Customer baska admin'i duzenleyemez
      if (req.admin.role === 'customer') {
        const existing = getAdminById(id);
        if (!existing || (existing.role || 'admin') !== 'customer') {
          return res.status(403).send('Bu kullaniciyi duzenleme yetkiniz yok.');
        }
      }
      const patch = {
        email: values.email,
        full_name: values.full_name || null,
        is_active: values.is_active,
        role: values.role,
        project_ids: values.project_ids,
      };
      if (values.password) {
        patch.password_hash = bcrypt.hashSync(values.password, 10);
      }
      updateAdmin(id, patch);

      if (req.session.adminUserId === id && values.is_active === false) {
        req.session.adminUserId = null;
        return res.redirect('/admin/login');
      }
    } else {
      const hash = bcrypt.hashSync(values.password, 10);
      createAdmin({
        email: values.email,
        password_hash: hash,
        full_name: values.full_name || null,
        is_active: values.is_active,
        role: values.role,
        project_ids: values.project_ids,
      });
    }
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    const allProjects = listProjects();
    return res.status(400).render('admin_user_edit', {
      title: id ? 'Kullanici Duzenle' : 'Kullanici Ekle',
      admin: req.admin,
      error: msg.includes('UNIQUE') ? 'Bu e-posta zaten kayıtlı.' : 'Kaydedilemedi.',
      user: id ? { id } : null,
      allProjects,
      values,
    });
  }

  res.redirect('/admin/users');
});

app.use((req, res) => {
  res.status(404).render('public_not_found', { title: 'Sayfa bulunamadı' });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Server running on ${BASE_URL}`);
});
