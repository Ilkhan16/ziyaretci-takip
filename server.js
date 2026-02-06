require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');

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
  req.admin = { id: admin.id, email: admin.email, full_name: admin.full_name, is_active: admin.is_active };
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

app.post('/p/:slug', (req, res) => {
  const project = getProjectBySlug(req.params.slug);
  if (!project || project.is_active !== 1) {
    return res.status(404).render('public_not_found', { title: 'Proje bulunamadı' });
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

  createEntry({
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

  res.render('public_success', {
    title: 'Kayıt alındı',
    project,
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
  res.redirect('/admin/entries');
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
  const projects = listProjects({ activeOnly: true }).sort((a, b) => a.name.localeCompare(b.name));

  const projectId = req.query.project_id ? Number(req.query.project_id) : null;
  const entryType = req.query.entry_type ? String(req.query.entry_type) : '';

  const normalizedProjectId = projectId && Number.isFinite(projectId) ? projectId : null;
  const normalizedEntryType = entryType && ['Ziyaretçi', 'Tedarikçi', 'Taşeron'].includes(entryType) ? entryType : '';

  const rawEntries = listEntries({
    projectId: normalizedProjectId || undefined,
    entryType: normalizedEntryType || undefined,
    limit: 500,
  });

  const projectMap = new Map(projects.map((p) => [p.id, p]));
  const entries = rawEntries.map((e) => {
    const p = projectMap.get(e.project_id) || null;
    return {
      ...e,
      project_name: p ? p.name : '',
      project_slug: p ? p.slug : '',
    };
  });

  res.render('admin_entries', {
    title: 'Kayıtlar',
    admin: req.admin,
    projects,
    entries,
    filters: {
      project_id: projectId || '',
      entry_type: entryType || '',
    },
  });
});

app.get('/admin/projects', requireAdmin, (req, res) => {
  const projects = listProjects();
  res.render('admin_projects', {
    title: 'Projeler',
    admin: req.admin,
    projects,
  });
});

app.get('/admin/projects/new', requireAdmin, (req, res) => {
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

app.get('/admin/projects/:id', requireAdmin, (req, res) => {
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

app.post('/admin/projects/save', requireAdmin, (req, res) => {
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
  const users = listAdmins().map((u) => ({
    id: u.id,
    email: u.email,
    full_name: u.full_name,
    is_active: u.is_active,
    created_at: u.created_at,
  }));
  res.render('admin_users', {
    title: 'Admin Kullanıcıları',
    admin: req.admin,
    users,
  });
});

app.get('/admin/users/new', requireAdmin, (req, res) => {
  res.render('admin_user_edit', {
    title: 'Admin Kullanıcısı Ekle',
    admin: req.admin,
    error: null,
    user: null,
    values: { email: '', full_name: '', password: '', is_active: true },
  });
});

app.get('/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = getAdminById(id);
  if (!user) return res.status(404).send('Not found');
  res.render('admin_user_edit', {
    title: 'Admin Kullanıcısı Düzenle',
    admin: req.admin,
    error: null,
    user,
    values: { email: user.email, full_name: user.full_name || '', password: '', is_active: user.is_active === 1 },
  });
});

app.post('/admin/users/save', requireAdmin, (req, res) => {
  const id = req.body.id ? Number(req.body.id) : null;

  const values = {
    email: (req.body.email || '').trim().toLowerCase(),
    full_name: (req.body.full_name || '').trim(),
    password: req.body.password || '',
    is_active: req.body.is_active === 'on',
  };

  const error =
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(values.email)
      ? 'Geçerli bir e-posta giriniz.'
      : !id && values.password.length < 6
        ? 'Şifre en az 6 karakter olmalıdır.'
        : null;

  if (error) {
    return res.status(400).render('admin_user_edit', {
      title: id ? 'Admin Kullanıcısı Düzenle' : 'Admin Kullanıcısı Ekle',
      admin: req.admin,
      error,
      user: id ? { id } : null,
      values,
    });
  }

  try {
    if (id) {
      if (values.password) {
        const hash = bcrypt.hashSync(values.password, 10);
        updateAdmin(id, {
          email: values.email,
          full_name: values.full_name || null,
          is_active: values.is_active,
          password_hash: hash,
        });
      } else {
        updateAdmin(id, {
          email: values.email,
          full_name: values.full_name || null,
          is_active: values.is_active,
        });
      }

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
      });
    }
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    return res.status(400).render('admin_user_edit', {
      title: id ? 'Admin Kullanıcısı Düzenle' : 'Admin Kullanıcısı Ekle',
      admin: req.admin,
      error: msg.includes('UNIQUE') ? 'Bu e-posta zaten kayıtlı.' : 'Kaydedilemedi.',
      user: id ? { id } : null,
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
