require('dotenv').config();

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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

const IS_PROD = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'change-me-please';
const JWT_COOKIE = 'auth_token';
const JWT_EXPIRES = '24h';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1); // Vercel / reverse proxy arkasinda gercek IP ve secure cookie icin

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

// ── JWT Auth helpers ──────────────────────────────────────────────

function setAuthCookie(res, adminUserId) {
  const token = jwt.sign({ adminUserId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  res.cookie(JWT_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    maxAge: 24 * 60 * 60 * 1000,
  });
}

function clearAuthCookie(res) {
  res.clearCookie(JWT_COOKIE);
}

async function requireAdmin(req, res, next) {
  try {
    const token = req.cookies[JWT_COOKIE];
    if (!token) return res.redirect('/admin/login');

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      clearAuthCookie(res);
      return res.redirect('/admin/login');
    }

    const admin = await getAdminById(decoded.adminUserId);
    if (!admin || admin.is_active !== 1) {
      clearAuthCookie(res);
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
  } catch (err) {
    next(err);
  }
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

// ── Rate limiter (IP bazlı, memory — best-effort in serverless) ───
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

// ── Mail gönderimi ───────────────────────────────────────────────
const MAIL_WEBHOOK_URL = (process.env.MAIL_WEBHOOK_URL || '').trim();
let mailTransporter = null;

// Öncelik: 1) Webhook (Google Apps Script), 2) SMTP
if (MAIL_WEBHOOK_URL) {
  console.log('✓ Mail webhook URL bulundu, HTTP tabanlı mail aktif');
} else {
  const smtpHost = (process.env.SMTP_HOST || '').trim();
  const smtpUser = (process.env.SMTP_USER || '').trim();
  const smtpPass = (process.env.SMTP_PASS || '').trim();
  if (smtpHost && smtpUser && smtpPass) {
    mailTransporter = nodemailer.createTransport({
      host: smtpHost, port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: smtpUser, pass: smtpPass },
      connectionTimeout: 10000, family: 4,
    });
    console.log('ℹ SMTP transport oluşturuldu');
    mailTransporter.verify().then(() => console.log('✓ SMTP mail bağlantısı başarılı'))
      .catch((e) => console.error('✗ SMTP verify hatası:', e.message));
  } else {
    console.log('ℹ Mail ayarları yapılmamış (MAIL_WEBHOOK_URL veya SMTP), mail gönderimi devre dışı');
  }
}

function buildMailHtml(project, entry) {
  const entryDate = new Date(entry.created_at).toLocaleString('tr-TR', { dateStyle: 'long', timeStyle: 'short' });
  return `
    <div style="font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;background:#ffffff;">
      <div style="background:linear-gradient(135deg,#6366f1 0%,#8b5cf6 100%);padding:28px 24px;border-radius:12px 12px 0 0;">
        <table style="width:100%"><tr>
          <td style="vertical-align:middle;">
            <div style="background:rgba(255,255,255,0.2);width:44px;height:44px;border-radius:10px;text-align:center;line-height:44px;font-size:18px;color:#fff;font-weight:bold;">Z</div>
          </td>
          <td style="vertical-align:middle;padding-left:14px;">
            <h1 style="margin:0;font-size:20px;font-weight:700;color:#ffffff;">${project.name}</h1>
            <p style="margin:4px 0 0;font-size:13px;color:rgba(255,255,255,0.85);">Yeni ${entry.entry_type.toLowerCase()} girişi kaydedildi</p>
          </td>
        </tr></table>
      </div>
      <div style="border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;overflow:hidden;">
        <div style="padding:20px 24px 0;">
          <span style="display:inline-block;background:${entry.entry_type === 'Ziyaretçi' ? '#dbeafe' : entry.entry_type === 'Tedarikçi' ? '#fef3c7' : '#fce7f3'};color:${entry.entry_type === 'Ziyaretçi' ? '#1e40af' : entry.entry_type === 'Tedarikçi' ? '#92400e' : '#9d174d'};font-size:12px;font-weight:600;padding:4px 12px;border-radius:20px;">${entry.entry_type.toUpperCase()}</span>
        </div>
        <div style="padding:16px 24px 20px;">
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:12px 0;border-bottom:1px solid #f1f5f9;color:#64748b;font-size:13px;width:110px;"><b>Ad Soyad</b></td><td style="padding:12px 0;border-bottom:1px solid #f1f5f9;font-size:15px;font-weight:600;color:#1e293b;">${entry.full_name}</td></tr>
            <tr><td style="padding:12px 0;border-bottom:1px solid #f1f5f9;color:#64748b;font-size:13px;"><b>Telefon</b></td><td style="padding:12px 0;border-bottom:1px solid #f1f5f9;font-size:14px;color:#334155;">${entry.phone}</td></tr>
            <tr><td style="padding:12px 0;border-bottom:1px solid #f1f5f9;color:#64748b;font-size:13px;"><b>Ziyaret Edilen</b></td><td style="padding:12px 0;border-bottom:1px solid #f1f5f9;font-size:14px;color:#334155;">${entry.visited_person}</td></tr>
            <tr><td style="padding:12px 0;color:#64748b;font-size:13px;"><b>Giriş Zamanı</b></td><td style="padding:12px 0;font-size:14px;color:#334155;">${entryDate}</td></tr>
          </table>
        </div>
        <div style="background:#f8fafc;padding:16px 24px;border-top:1px solid #e2e8f0;">
          <table style="width:100%"><tr>
            <td style="font-size:11px;color:#94a3b8;">Bu e-posta otomatik olarak gönderilmiştir.</td>
            <td style="text-align:right;font-size:11px;color:#94a3b8;">Ziyaretçi Takip Sistemi</td>
          </tr></table>
        </div>
      </div>
    </div>`;
}

async function sendViaWebhook(to, subject, html) {
  const res = await fetch(MAIL_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: Array.isArray(to) ? to.join(',') : to, subject, html }),
  });
  if (!res.ok) throw new Error(`Webhook ${res.status}`);
  return res.json();
}

function sendEntryNotification(project, entry) {
  const recipients = safeArray(project.email_recipients).filter((e) => e && e.includes('@'));
  if (!recipients.length) return;

  const subject = `[${project.name}] Yeni ${entry.entry_type} Girişi - ${entry.full_name}`;
  const html = buildMailHtml(project, entry);

  if (MAIL_WEBHOOK_URL) {
    sendViaWebhook(recipients, subject, html)
      .then(() => console.log('✓ Mail gönderildi (Webhook)'))
      .catch((err) => console.error('✗ Webhook mail hatası:', err.message));
  } else if (mailTransporter) {
    mailTransporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER, to: recipients.join(', '), subject, html,
    }).then(() => console.log('✓ Mail gönderildi (SMTP)'))
      .catch((err) => console.error('✗ SMTP mail hatası:', err.message));
  }
}

app.get('/', (req, res) => {
  res.redirect('/admin');
});

// Gecici debug — login sorununu teshis et
app.get('/debug-login', async (req, res) => {
  try {
    const email = (process.env.SEED_ADMIN_EMAIL || '').trim().toLowerCase();
    const password = process.env.SEED_ADMIN_PASSWORD || '';
    const user = await getAdminByEmail(email);
    if (!user) {
      return res.send(`<pre>Admin bulunamadi: ${email}\nDB'de kayit yok. Once /setup'a git.</pre>`);
    }
    const hashOk = bcrypt.compareSync(password, user.password_hash);
    res.send(`<pre>
email: ${user.email}
id: ${user.id} (type: ${typeof user.id})
is_active: ${user.is_active} (type: ${typeof user.is_active})
!is_active: ${!user.is_active}
password_hash ilk 20: ${(user.password_hash || '').slice(0, 20)}...
SEED password: ${password}
bcrypt match: ${hashOk}
role: ${user.role}
</pre>`);
  } catch (err) {
    res.status(500).send(`<pre>HATA: ${err.stack}</pre>`);
  }
});

// Kurulum — admin yoksa olustur, varsa sifre sifirla
app.get('/setup', async (req, res) => {
  try {
    const email = (process.env.SEED_ADMIN_EMAIL || '').trim().toLowerCase();
    const password = (process.env.SEED_ADMIN_PASSWORD || '').trim();
    if (!email || !password) {
      return res.status(500).send('SEED_ADMIN_EMAIL ve SEED_ADMIN_PASSWORD env degiskenleri tanimlanmamis.');
    }
    const hash = bcrypt.hashSync(password, 10);
    const existing = await getAdminByEmail(email);
    if (existing) {
      await updateAdmin(existing.id, { password_hash: hash, is_active: true });
      res.send(`<h2>Sifre sifirlandi!</h2><p>Admin: <b>${email}</b></p><p><a href="/admin/login">Girise git</a></p>`);
    } else {
      await createAdmin({
        email,
        password_hash: hash,
        full_name: process.env.SEED_ADMIN_FULL_NAME || 'Admin',
        is_active: true,
        role: 'admin',
        project_ids: [],
      });
      res.send(`<h2>Kurulum tamamlandi!</h2><p>Admin: <b>${email}</b></p><p><a href="/admin/login">Girise git</a></p>`);
    }
  } catch (err) {
    res.status(500).send(`<h2>Hata</h2><pre>${err.stack || err.message}</pre>`);
  }
});

// TC lookup API — returns last entry info for auto-fill
app.get('/api/tc-lookup/:tc', async (req, res, next) => {
  try {
    const tc = (req.params.tc || '').trim();
    if (!/^[0-9]{11}$/.test(tc)) return res.json({ found: false });
    const entry = await getLastEntryByTc(tc);
    if (!entry) return res.json({ found: false });
    res.json({
      found: true,
      full_name: entry.full_name,
      phone: entry.phone,
      entry_type: entry.entry_type,
    });
  } catch (err) { next(err); }
});

// Public form (project specific)
app.get('/p/:slug', async (req, res, next) => {
  try {
    const project = await getProjectBySlug(req.params.slug);
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
  } catch (err) { next(err); }
});

app.post('/p/:slug', rateLimit, async (req, res, next) => {
  try {
    const project = await getProjectBySlug(req.params.slug);
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

    const entry = await createEntry({
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
  } catch (err) { next(err); }
});

// QR page & QR PNG for project
app.get('/p/:slug/qr', async (req, res, next) => {
  try {
    const project = await getProjectBySlug(req.params.slug);
    if (!project || project.is_active !== 1) {
      return res.status(404).render('public_not_found', { title: 'Proje bulunamadı' });
    }
    const formUrl = `${BASE_URL}/p/${project.slug}`;
    res.render('public_qr', {
      title: `${project.name} - QR`,
      project,
      formUrl,
    });
  } catch (err) { next(err); }
});

app.get('/p/:slug/qr.png', async (req, res, next) => {
  try {
    const project = await getProjectBySlug(req.params.slug);
    if (!project || project.is_active !== 1) {
      return res.status(404).end();
    }
    const formUrl = `${BASE_URL}/p/${project.slug}`;
    const pngBuffer = await QRCode.toBuffer(formUrl, {
      type: 'png',
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 512,
    });
    res.setHeader('Content-Type', 'image/png');
    res.send(pngBuffer);
  } catch (err) { next(err); }
});

// Admin
app.get('/admin', requireAdmin, (req, res) => {
  res.redirect('/admin/dashboard');
});

// Dashboard
app.get('/admin/dashboard', requireAdmin, async (req, res, next) => {
  try {
    let allProjects = await listProjects({ activeOnly: false });
    if (req.admin.role === 'customer') {
      allProjects = allProjects.filter((p) => req.admin.project_ids.includes(p.id));
    }

    const allEntries = await listEntries({ limit: 50000 });
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
  } catch (err) { next(err); }
});

app.get('/admin/login', (req, res) => {
  res.render('admin_login', {
    title: 'Admin Giriş',
    error: null,
    values: { email: '' },
  });
});

app.post('/admin/login', async (req, res, next) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';

    const user = await getAdminByEmail(email);

    // Gecici debug — login hatasi nerede
    const seedPw = process.env.SEED_ADMIN_PASSWORD || '';
    const pwMatch = password === seedPw;
    const checks = {
      userFound: !!user,
      isActive: user ? !!user.is_active : false,
      bcryptMatch: user && user.password_hash ? bcrypt.compareSync(password, user.password_hash) : false,
      pwLen: password.length,
      seedLen: seedPw.length,
      pwSame: pwMatch,
      pwHex: Buffer.from(password).toString('hex'),
      seedHex: Buffer.from(seedPw).toString('hex'),
    };

    if (!user || !user.is_active || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).render('admin_login', {
        title: 'Admin Giriş',
        error: `Hata. [found=${checks.userFound} active=${checks.isActive} bcrypt=${checks.bcryptMatch} pwLen=${checks.pwLen} seedLen=${checks.seedLen} same=${checks.pwSame} pwHex=${checks.pwHex} seedHex=${checks.seedHex}]`,
        values: { email },
      });
    }

    setAuthCookie(res, user.id);
    res.redirect('/admin');
  } catch (err) { next(err); }
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  clearAuthCookie(res);
  res.redirect('/admin/login');
});

app.get('/admin/entries', requireAdmin, async (req, res, next) => {
  try {
    let projects = (await listProjects({ activeOnly: false })).sort((a, b) => a.name.localeCompare(b.name));

    if (req.admin.role === 'customer') {
      projects = projects.filter((p) => req.admin.project_ids.includes(p.id));
    }

    const projectId = req.query.project_id ? Number(req.query.project_id) : null;
    const entryType = req.query.entry_type ? String(req.query.entry_type) : '';
    const durum = req.query.durum || '';
    const search = (req.query.search || '').trim().toLowerCase();
    const dateFrom = (req.query.date_from || '').trim();
    const dateTo = (req.query.date_to || '').trim();

    const normalizedProjectId = projectId && Number.isFinite(projectId) ? projectId : null;
    const normalizedEntryType = entryType && ['Ziyaretçi', 'Tedarikçi', 'Taşeron'].includes(entryType) ? entryType : '';

    if (req.admin.role === 'customer' && normalizedProjectId && !req.admin.project_ids.includes(normalizedProjectId)) {
      return res.status(403).send('Bu projeye erişim yetkiniz yok.');
    }

    const rawEntries = await listEntries({
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

    // Durum filtresi
    if (durum === 'icerde') {
      entries = entries.filter((e) => !e.exit_at);
    } else if (durum === 'cikti') {
      entries = entries.filter((e) => !!e.exit_at);
    }

    // Arama filtresi (isim, TC, telefon, ziyaret edilen)
    if (search) {
      entries = entries.filter((e) =>
        (e.full_name || '').toLowerCase().includes(search) ||
        (e.tc_kimlik_no || '').includes(search) ||
        (e.phone || '').includes(search) ||
        (e.visited_person || '').toLowerCase().includes(search)
      );
    }

    // Tarih filtresi
    if (dateFrom) {
      entries = entries.filter((e) => e.created_at && e.created_at.slice(0, 10) >= dateFrom);
    }
    if (dateTo) {
      entries = entries.filter((e) => e.created_at && e.created_at.slice(0, 10) <= dateTo);
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
        search: search || '',
        date_from: dateFrom || '',
        date_to: dateTo || '',
      },
    });
  } catch (err) { next(err); }
});

// Bulk exit — mark all active visitors as left
app.post('/admin/entries/bulk-exit', requireAdmin, async (req, res, next) => {
  try {
    const allEntries = await listEntries({ limit: 50000 });
    let active = allEntries.filter((e) => !e.exit_at);
    if (req.admin.role === 'customer') {
      active = active.filter((e) => req.admin.project_ids.includes(e.project_id));
    }
    await Promise.all(active.map((e) => updateEntryExit(e.id)));
    res.redirect('/admin/entries?durum=icerde');
  } catch (err) { next(err); }
});

// Entry exit — mark visitor as left
app.post('/admin/entries/:id/exit', requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const entry = await getEntryById(id);
    if (!entry) return res.status(404).send('Kayit bulunamadi.');
    if (req.admin.role === 'customer' && !req.admin.project_ids.includes(entry.project_id)) {
      return res.status(403).send('Yetkiniz yok.');
    }
    if (!entry.exit_at) {
      await updateEntryExit(id);
    }
    res.redirect('/admin/entries' + (req.body.redirect_query || ''));
  } catch (err) { next(err); }
});

// Visitor card print page
app.get('/admin/entries/:id/print', requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const entry = await getEntryById(id);
    if (!entry) return res.status(404).send('Kayit bulunamadi.');

    // Customer yetki kontrolu
    if (req.admin.role === 'customer' && !req.admin.project_ids.includes(entry.project_id)) {
      return res.status(403).send('Bu kayda erisim yetkiniz yok.');
    }

    const project = await getProjectById(entry.project_id);
    res.render('print_visitor_card', {
      title: 'Ziyaretci Karti',
      entry,
      project,
    });
  } catch (err) { next(err); }
});

// Excel CSV export
app.get('/admin/entries/export', requireAdmin, async (req, res, next) => {
  try {
    let projects = await listProjects({ activeOnly: false });
    if (req.admin.role === 'customer') {
      projects = projects.filter((p) => req.admin.project_ids.includes(p.id));
    }

    const projectId = req.query.project_id ? Number(req.query.project_id) : null;
    const entryType = req.query.entry_type ? String(req.query.entry_type) : '';

    if (req.admin.role === 'customer' && projectId && !req.admin.project_ids.includes(projectId)) {
      return res.status(403).send('Yetkiniz yok.');
    }

    let rawEntries = await listEntries({
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
  } catch (err) { next(err); }
});

app.get('/admin/projects', requireAdmin, requireSuperAdmin, async (req, res, next) => {
  try {
    const projects = await listProjects();
    res.render('admin_projects', {
      title: 'Projeler',
      admin: req.admin,
      projects,
    });
  } catch (err) { next(err); }
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

app.get('/admin/projects/:id', requireAdmin, requireSuperAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const project = await getProjectById(id);
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
  } catch (err) { next(err); }
});

app.post('/admin/projects/save', requireAdmin, requireSuperAdmin, async (req, res, next) => {
  try {
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
      ? values.authorized_people_lines.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
      : [];

    const emailRecipients = values.email_recipients_lines
      ? values.email_recipients_lines.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
      : [];

    try {
      await saveProject({
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
  } catch (err) { next(err); }
});

app.get('/admin/users', requireAdmin, async (req, res, next) => {
  try {
    let users = (await listAdmins()).map((u) => ({
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
  } catch (err) { next(err); }
});

app.get('/admin/users/new', requireAdmin, async (req, res, next) => {
  try {
    let allProjects = await listProjects();
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
  } catch (err) { next(err); }
});

app.get('/admin/users/:id', requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const user = await getAdminById(id);
    if (!user) return res.status(404).send('Not found');
    // Customer baska admin'i duzenleyemez, sadece kendi projelerindeki customer'lari
    if (req.admin.role === 'customer') {
      const uPids = Array.isArray(user.project_ids) ? user.project_ids : [];
      if ((user.role || 'admin') !== 'customer' || !uPids.some((pid) => req.admin.project_ids.includes(pid))) {
        return res.status(403).send('Bu kullaniciyi duzenleme yetkiniz yok.');
      }
    }
    let allProjects = await listProjects();
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
  } catch (err) { next(err); }
});

app.post('/admin/users/save', requireAdmin, async (req, res, next) => {
  try {
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
      values.role = 'customer';
      values.project_ids = values.project_ids.filter((pid) => req.admin.project_ids.includes(pid));
    }

    const error =
      !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(values.email)
        ? 'Geçerli bir e-posta giriniz.'
        : !id && values.password.length < 6
          ? 'Şifre en az 6 karakter olmalıdır.'
          : null;

    if (error) {
      let allProjects = await listProjects();
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
          const existing = await getAdminById(id);
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
        await updateAdmin(id, patch);

        // Kendi hesabini deaktive eden admin'i cikis yaptir
        const tokenPayload = req.cookies[JWT_COOKIE] ? jwt.decode(req.cookies[JWT_COOKIE]) : null;
        if (tokenPayload && tokenPayload.adminUserId === id && values.is_active === false) {
          clearAuthCookie(res);
          return res.redirect('/admin/login');
        }
      } else {
        const hash = bcrypt.hashSync(values.password, 10);
        await createAdmin({
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
      const allProjects = await listProjects();
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
  } catch (err) { next(err); }
});

// Sifre degistirme
app.get('/admin/change-password', requireAdmin, (req, res) => {
  res.render('admin_change_password', {
    title: 'Şifre Değiştir',
    admin: req.admin,
    error: null,
    success: null,
  });
});

app.post('/admin/change-password', requireAdmin, async (req, res, next) => {
  try {
    const currentPassword = req.body.current_password || '';
    const newPassword = req.body.new_password || '';
    const confirmPassword = req.body.confirm_password || '';

    const user = await getAdminById(req.admin.id);
    if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
      return res.status(400).render('admin_change_password', {
        title: 'Şifre Değiştir', admin: req.admin,
        error: 'Mevcut şifre hatalı.', success: null,
      });
    }
    if (newPassword.length < 6) {
      return res.status(400).render('admin_change_password', {
        title: 'Şifre Değiştir', admin: req.admin,
        error: 'Yeni şifre en az 6 karakter olmalıdır.', success: null,
      });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).render('admin_change_password', {
        title: 'Şifre Değiştir', admin: req.admin,
        error: 'Yeni şifreler eşleşmiyor.', success: null,
      });
    }

    await updateAdmin(req.admin.id, { password_hash: bcrypt.hashSync(newPassword, 10) });
    setAuthCookie(res, req.admin.id);
    res.render('admin_change_password', {
      title: 'Şifre Değiştir', admin: req.admin,
      error: null, success: 'Şifreniz başarıyla değiştirildi.',
    });
  } catch (err) { next(err); }
});

app.use((req, res) => {
  res.status(404).render('public_not_found', { title: 'Sayfa bulunamadı' });
});

// Global error handler
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('Uygulama hatası:', err);
  res.status(500).render('public_error', {
    title: 'Sunucu Hatası',
    message: 'Beklenmeyen bir hata oluştu. Lütfen tekrar deneyin.',
  });
});

// Vercel serverless icin app'i export et; local dev icin listen
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on ${BASE_URL}`);
  });
}

module.exports = app;
