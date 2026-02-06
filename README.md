# Ziyaretçi Takip (Web) - QR ile Giriş Kayıt

Bu proje **mobil uygulama olmadan**, sadece tarayıcı üzerinden çalışan QR tabanlı giriş kayıt sistemidir.

## Özellikler

- Proje bazlı URL (ör. `/p/proje-1`) ve QR üretimi (`/p/proje-1/qr`)
- Form alanları:
  - Giriş Türü: Ziyaretçi / Tedarikçi / Taşeron
  - TC Kimlik No, Ad Soyad, Cep Telefonu
  - Projeye özel Yetkili/Müşteri listesi (açılır liste)
  - Not
- İSG akışı:
  - Giriş türüne göre farklı İSG metni
  - İSG onayı zorunlu (checkbox işaretlenmeden gönderilemez)
- Kayıt sırasında otomatik:
  - Tarih/saat (DB tarafında)
  - IP adresi
- Admin panel:
  - Çoklu admin kullanıcı
  - Proje yönetimi (yetkili listesi, İSG metinleri, mail alıcıları)
  - Kayıt listeleme + Proje/Giriş türü filtreleme

> Not: Otomatik e-posta gönderimi bu sürümde **kapalı** (altyapı için mail alıcıları proje ayarlarında tutulur).

---

## Kurulum (Windows)

Ön koşul: Node.js LTS kurulu olmalı.

1) Bağımlılıkları yükle:

```bash
npm install
```

2) Ortam değişkenlerini ayarla:

- `.env.example` dosyasını kopyalayıp `.env` yap
- İçindeki değerleri düzenle

3) İlk admin kullanıcısını oluştur:

```bash
npm run seed
```

4) Uygulamayı çalıştır:

```bash
npm run dev
```

Uygulama varsayılan olarak:

- `http://localhost:3000`

---

## Kullanım

### 1) Admin giriş

- `http://localhost:3000/admin`
- `.env` içindeki seed ile oluşturduğun admin hesabıyla giriş yap

### 2) Proje oluştur

- Admin panel → **Projeler** → **Proje Ekle**
- `slug`: QR ile paylaşacağın proje linkinin son kısmıdır.

### 3) QR ve form linki

- Form: `http://localhost:3000/p/<slug>`
- QR sayfası: `http://localhost:3000/p/<slug>/qr`
- QR PNG: `http://localhost:3000/p/<slug>/qr.png`

Bu URL’yi kullanarak projeye özel QR kodu basıp sahada okutabilirsin.

---

## Veritabanı

- JSON dosyası: `data.json`
- Koleksiyonlar: `admin_users`, `projects`, `entries`

---

## E-posta (sonraki adım)

E-posta gönderimi istenirse:

- Proje bazlı alıcılar proje kaydında `email_recipients` alanında hazır
- `server.js` içindeki kayıt sonrası akışa SMTP/servis entegrasyonu eklenebilir
