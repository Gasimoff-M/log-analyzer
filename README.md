# 📋 Log Analiz ve Anomali Tespit Aracı

Sistem ve sunucu loglarını otomatik analiz eden, brute-force saldırıları, web taramaları ve şüpheli aktiviteleri tespit eden Python aracı.

## 🚀 Özellikler

- SSH brute-force saldırısı tespiti
- Başarısız → Başarılı giriş anomalisi (credential stuffing)
- HTTP fuzzing / web tarama tespiti
- Tehlikeli sudo komutu uyarısı
- Demo mod (log dosyası olmadan test edilebilir)
- Detaylı renkli terminal raporu

## 📦 Kurulum

```bash
git clone https://github.com/Gasimoff-M/log-analyzer
cd log-analyzer
python log_analyzer.py
```

> Python 3.x gereklidir. Harici kütüphane gerekmez.

## 💻 Kullanım

```
  Log kaynağını seçin:
  1 - Demo log (test için örnek veri)
  2 - Dosyadan log oku

  Seçiminiz [1/2]: 1
```

## 📊 Örnek Çıktı

```
============================================================
  LOG ANALİZ RAPORU
  Tarih  : 02.05.2025 14:35:00
============================================================

  📊 GENEL İSTATİSTİKLER:
  Toplam satır analiz edildi : 26
  SSH başarısız giriş        : 7
  SSH başarılı giriş         : 2
  HTTP isteği                : 15
  Sudo kullanımı             : 2

  🔑 EN ÇOK BAŞARISIZ GİRİŞ YAPAN IP'LER:
  192.168.1.100        → 5 deneme

  🚨 TESPİT EDİLEN ANOMALİLER (3 adet):

  1. 🔴 Brute-Force Saldırısı
     IP    : 192.168.1.100
     Detay : 5 başarısız giriş denemesi — Hedef kullanıcılar: root, admin, user

  2. 🟠 Şüpheli Giriş
     IP    : 192.168.1.100
     Detay : Önce 5 başarısız, sonra başarılı SSH girişi yapıldı.

  3. 🟡 Web Tarama / Fuzzing
     IP    : 192.168.1.200
     Detay : 20 adet HTTP hata kodu üretildi (4xx/5xx).
```

## ⚠️ Yasal Uyarı

Bu araç yalnızca **eğitim amaçlı** ve **yetkili sistemlerde** kullanım içindir.

## 👤 Geliştirici

**Gasimoff-M** — [github.com/Gasimoff-M](https://github.com/Gasimoff-M)
