require('dotenv').config();
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || __dirname;
const dataPath = path.join(DATA_DIR, 'data.json');

// Kac adet fake kayit olusturulsun
const ENTRY_COUNT = parseInt(process.argv[2] || '500', 10);

const NAMES = [
  'Ahmet Yılmaz', 'Mehmet Kaya', 'Ali Demir', 'Hasan Çelik', 'Hüseyin Şahin',
  'Mustafa Yıldız', 'İbrahim Öztürk', 'Osman Aydın', 'İsmail Arslan', 'Murat Doğan',
  'Fatma Kılıç', 'Ayşe Aslan', 'Emine Koç', 'Hatice Korkmaz', 'Zeynep Çetin',
  'Elif Özdemir', 'Merve Kaplan', 'Sultan Güneş', 'Büşra Erdoğan', 'Seda Bulut',
  'Yusuf Karaca', 'Emre Aktaş', 'Burak Tekin', 'Serkan Polat', 'Onur Eren',
  'Deniz Aksoy', 'Can Yalçın', 'Tolga Güler', 'Barış Kurt', 'Kemal Özkan',
];

const PHONES = [];
for (let i = 0; i < 50; i++) {
  PHONES.push('05' + String(Math.floor(Math.random() * 100)).padStart(2, '0') + ' ' +
    String(Math.floor(Math.random() * 1000)).padStart(3, '0') + ' ' +
    String(Math.floor(Math.random() * 10000)).padStart(4, '0'));
}

const VISITED = [
  'Ahmet Bey', 'Mehmet Mühendis', 'Proje Müdürü', 'Şantiye Şefi', 'İnsan Kaynakları',
  'Güvenlik Amiri', 'Satın Alma', 'Teknik Müdür', 'İş Güvenliği Uzmanı', 'Depo Sorumlusu',
];

const ENTRY_TYPES = ['Ziyaretçi', 'Tedarikçi', 'Taşeron'];
const TYPE_WEIGHTS = [0.5, 0.3, 0.2]; // %50 ziyaretci, %30 tedarikci, %20 taseron

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function pickWeighted(arr, weights) {
  const r = Math.random();
  let sum = 0;
  for (let i = 0; i < arr.length; i++) { sum += weights[i]; if (r < sum) return arr[i]; }
  return arr[arr.length - 1];
}
function randomTc() {
  let tc = String(Math.floor(Math.random() * 9) + 1);
  for (let i = 0; i < 10; i++) tc += String(Math.floor(Math.random() * 10));
  return tc;
}
function randomDate(daysBack) {
  const now = Date.now();
  const past = now - daysBack * 24 * 60 * 60 * 1000;
  return new Date(past + Math.random() * (now - past));
}

// Load existing data
let data;
if (fs.existsSync(dataPath)) {
  data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
} else {
  console.log('data.json bulunamadi. Once npm run seed ile admin olusturun.');
  process.exit(1);
}

if (!data.projects || !data.projects.length) {
  console.log('Hic proje yok. Once admin panelden proje ekleyin.');
  process.exit(1);
}

const projectIds = data.projects.map(p => p.id);
let counter = data.counters.entries || 0;

console.log(`${ENTRY_COUNT} fake kayit olusturuluyor...`);
console.log(`Mevcut projeler: ${data.projects.map(p => p.name).join(', ')}`);

const newEntries = [];
for (let i = 0; i < ENTRY_COUNT; i++) {
  counter++;
  const createdAt = randomDate(90); // son 90 gun
  const hasExit = Math.random() < 0.85; // %85'i cikmis
  const exitAt = hasExit
    ? new Date(createdAt.getTime() + (15 + Math.random() * 480) * 60000) // 15dk - 8saat arasi
    : null;

  newEntries.push({
    id: counter,
    project_id: pick(projectIds),
    entry_type: pickWeighted(ENTRY_TYPES, TYPE_WEIGHTS),
    tc_kimlik_no: randomTc(),
    full_name: pick(NAMES),
    phone: pick(PHONES),
    visited_person: pick(VISITED),
    note: null,
    isg_accepted: 1,
    ip_address: '192.168.1.' + Math.floor(Math.random() * 255),
    created_at: createdAt.toISOString(),
    exit_at: exitAt ? exitAt.toISOString() : undefined,
  });
}

data.entries = data.entries.concat(newEntries);
data.counters.entries = counter;

const jsonStr = JSON.stringify(data, null, 2);
const sizeMB = (Buffer.byteLength(jsonStr, 'utf8') / (1024 * 1024)).toFixed(2);

fs.writeFileSync(dataPath, jsonStr, 'utf8');

console.log(`\n✓ ${ENTRY_COUNT} kayit eklendi. Toplam: ${data.entries.length} kayit`);
console.log(`✓ data.json boyutu: ${sizeMB} MB`);
console.log(`✓ 500MB Volume ile yaklasik ${Math.floor(500 / parseFloat(sizeMB) * data.entries.length)} kayit tutabilirsiniz`);
