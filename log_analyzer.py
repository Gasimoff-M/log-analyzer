# =====================================================
# Log Analiz ve Anomali Tespit Aracı
# Geliştirici: Gasimoff-M
# Açıklama: Sistem loglarını analiz ederek şüpheli
#            aktiviteleri ve anomalileri tespit eder
# =====================================================

import re
import os
from datetime import datetime
from collections import defaultdict

# ─── Renk Kodları ──────────────────────────────────────
KIRMIZI = "\033[91m"
YESIL   = "\033[92m"
SARI    = "\033[93m"
MAVI    = "\033[94m"
BEYAZ   = "\033[97m"
SIFIRLA = "\033[0m"

# ─── Tespit Eşikleri ───────────────────────────────────
BRUTE_FORCE_ESIK   = 5   # Aynı IP'den kaç başarısız girişte alarm verilsin
TARAMA_ESIK        = 10  # Aynı IP'den kaç farklı porta erişimde alarm verilsin
HATA_ESIK          = 20  # Kaç HTTP hatasında alarm verilsin

# ─── Regex Kalıpları ───────────────────────────────────

# SSH başarısız giriş: "Failed password for root from 192.168.1.1 port 22"
SSH_BASARISIZ = re.compile(
    r"Failed password for (\w+) from ([\d\.]+) port (\d+)"
)

# SSH başarılı giriş: "Accepted password for user from 192.168.1.1 port 22"
SSH_BASARILI = re.compile(
    r"Accepted password for (\w+) from ([\d\.]+) port (\d+)"
)

# Apache/Nginx erişim logu: 192.168.1.1 - - [01/Jan/2025:12:00:00] "GET /page HTTP/1.1" 200
HTTP_ERISIM = re.compile(
    r'([\d\.]+) .+ \[(.+?)\] "(\w+) (.+?) HTTP.+?" (\d{3})'
)

# Sudo kullanımı: "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
SUDO_KULLANIM = re.compile(
    r"(\w+) : TTY=.+ COMMAND=(.+)"
)


class LogAnalizci:
    def __init__(self):
        # Verileri saklamak için sözlükler
        self.basarisiz_girisler   = defaultdict(list)   # IP -> [kullanıcı listesi]
        self.basarili_girisler    = defaultdict(list)
        self.http_hatalar         = defaultdict(int)     # IP -> hata sayısı
        self.sudo_kullanicilari   = defaultdict(list)
        self.anomaliler           = []
        self.istatistik           = {
            "toplam_satir"        : 0,
            "ssh_basarisiz"       : 0,
            "ssh_basarili"        : 0,
            "http_istekleri"      : 0,
            "sudo_kullanim"       : 0,
        }

    def satir_analiz_et(self, satir):
        """Her log satırını regex ile analiz eder."""
        self.istatistik["toplam_satir"] += 1

        # SSH başarısız giriş kontrolü
        eslesme = SSH_BASARISIZ.search(satir)
        if eslesme:
            kullanici, ip, port = eslesme.groups()
            self.basarisiz_girisler[ip].append(kullanici)
            self.istatistik["ssh_basarisiz"] += 1

        # SSH başarılı giriş kontrolü
        eslesme = SSH_BASARILI.search(satir)
        if eslesme:
            kullanici, ip, port = eslesme.groups()
            self.basarili_girisler[ip].append(kullanici)
            self.istatistik["ssh_basarili"] += 1

        # HTTP erişim logu kontrolü
        eslesme = HTTP_ERISIM.search(satir)
        if eslesme:
            ip, tarih, metod, yol, durum_kodu = eslesme.groups()
            self.istatistik["http_istekleri"] += 1
            # 4xx ve 5xx hata kodlarını say
            if durum_kodu.startswith(("4", "5")):
                self.http_hatalar[ip] += 1

        # Sudo kullanımı kontrolü
        eslesme = SUDO_KULLANIM.search(satir)
        if eslesme:
            kullanici, komut = eslesme.groups()
            self.sudo_kullanicilari[kullanici].append(komut)
            self.istatistik["sudo_kullanim"] += 1

    def anomali_tespit_et(self):
        """Toplanan verileri eşiklerle karşılaştırarak anomali tespit eder."""

        # Brute-force saldırısı tespiti
        for ip, girisler in self.basarisiz_girisler.items():
            if len(girisler) >= BRUTE_FORCE_ESIK:
                self.anomaliler.append({
                    "tur"    : "🔴 Brute-Force Saldırısı",
                    "ip"     : ip,
                    "detay"  : f"{len(girisler)} başarısız giriş denemesi — "
                               f"Hedef kullanıcılar: {', '.join(set(girisler))}"
                })

        # Başarısız sonra başarılı giriş (credential stuffing belirtisi)
        for ip in self.basarili_girisler:
            if ip in self.basarisiz_girisler:
                self.anomaliler.append({
                    "tur"   : "🟠 Şüpheli Giriş",
                    "ip"    : ip,
                    "detay" : f"Önce {len(self.basarisiz_girisler[ip])} başarısız, "
                              f"sonra başarılı SSH girişi yapıldı."
                })

        # Aşırı HTTP hata üretimi (tarama/fuzzing belirtisi)
        for ip, sayi in self.http_hatalar.items():
            if sayi >= HATA_ESIK:
                self.anomaliler.append({
                    "tur"   : "🟡 Web Tarama / Fuzzing",
                    "ip"    : ip,
                    "detay" : f"{sayi} adet HTTP hata kodu üretildi (4xx/5xx)."
                })

        # Tehlikeli sudo komutları
        tehlikeli_komutlar = ["/bin/bash", "/bin/sh", "chmod 777", "nc ", "ncat"]
        for kullanici, komutlar in self.sudo_kullanicilari.items():
            for komut in komutlar:
                for tehlikeli in tehlikeli_komutlar:
                    if tehlikeli in komut:
                        self.anomaliler.append({
                            "tur"   : "🔴 Tehlikeli Sudo Komutu",
                            "ip"    : "localhost",
                            "detay" : f"Kullanıcı '{kullanici}' sudo ile çalıştırdı: {komut.strip()}"
                        })

    def rapor_yazdir(self, dosya_adi=""):
        """Analiz sonuçlarını raporlar."""
        print("\n" + "=" * 60)
        print(f"  LOG ANALİZ RAPORU")
        print(f"  Tarih  : {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
        if dosya_adi:
            print(f"  Dosya  : {dosya_adi}")
        print("=" * 60)

        # İstatistikler
        print(f"\n{MAVI}  📊 GENEL İSTATİSTİKLER:{SIFIRLA}")
        print(f"  Toplam satır analiz edildi : {self.istatistik['toplam_satir']}")
        print(f"  SSH başarısız giriş        : {self.istatistik['ssh_basarisiz']}")
        print(f"  SSH başarılı giriş         : {self.istatistik['ssh_basarili']}")
        print(f"  HTTP isteği                : {self.istatistik['http_istekleri']}")
        print(f"  Sudo kullanımı             : {self.istatistik['sudo_kullanim']}")

        # En çok başarısız giriş yapan IP'ler
        if self.basarisiz_girisler:
            print(f"\n{SARI}  🔑 EN ÇOK BAŞARISIZ GİRİŞ YAPAN IP'LER:{SIFIRLA}")
            sirali = sorted(self.basarisiz_girisler.items(),
                            key=lambda x: len(x[1]), reverse=True)[:5]
            for ip, girisler in sirali:
                print(f"  {ip:<20} → {len(girisler)} deneme")

        # Anomaliler
        print(f"\n{KIRMIZI}  🚨 TESPİT EDİLEN ANOMALİLER ({len(self.anomaliler)} adet):{SIFIRLA}")
        if not self.anomaliler:
            print(f"{YESIL}  [✓] Anomali tespit edilmedi.{SIFIRLA}")
        else:
            for i, a in enumerate(self.anomaliler, 1):
                print(f"\n  {i}. {a['tur']}")
                print(f"     IP    : {a['ip']}")
                print(f"     Detay : {a['detay']}")

        print("\n" + "=" * 60)


def demo_log_olustur():
    """
    Gerçekçi örnek log içeriği oluşturur.
    Gerçek log dosyan yoksa bununla test edebilirsin.
    """
    demo = """
Jan 15 10:23:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:03 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:05 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 10:23:07 server sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2
Jan 15 10:23:09 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:11 server sshd[1234]: Accepted password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:24:00 server sshd[1235]: Failed password for admin from 10.0.0.5 port 22 ssh2
Jan 15 10:24:01 server sshd[1235]: Failed password for admin from 10.0.0.5 port 22 ssh2
Jan 15 11:00:00 server sudo: adminuser : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash
Jan 15 11:05:00 server sudo: devuser : TTY=pts/1 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/apt
192.168.1.200 - - [15/Jan/2025:12:00:01 +0000] "GET /admin HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:02 +0000] "GET /wp-login.php HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:04 +0000] "GET /.env HTTP/1.1" 403 256
192.168.1.200 - - [15/Jan/2025:12:00:05 +0000] "GET /backup.zip HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:06 +0000] "GET /config.php HTTP/1.1" 403 256
192.168.1.200 - - [15/Jan/2025:12:00:07 +0000] "GET /shell.php HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:08 +0000] "GET /test.php HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:09 +0000] "GET /db.php HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:10 +0000] "GET /setup.php HTTP/1.1" 404 512
192.168.1.200 - - [15/Jan/2025:12:00:11 +0000] "GET /install.php HTTP/1.1" 500 1024
192.168.1.200 - - [15/Jan/2025:12:00:12 +0000] "GET /old/ HTTP/1.1" 403 256
192.168.1.200 - - [15/Jan/2025:12:00:13 +0000] "GET /api/users HTTP/1.1" 401 128
192.168.1.200 - - [15/Jan/2025:12:00:14 +0000] "POST /login HTTP/1.1" 401 128
192.168.1.200 - - [15/Jan/2025:12:00:15 +0000] "GET /robots.txt HTTP/1.1" 200 64
Jan 15 14:00:00 server sshd[9999]: Accepted password for deploy from 172.16.0.1 port 22 ssh2
""".strip()
    return demo


# ─── Ana Program ───────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{MAVI}╔══════════════════════════════════════════╗")
    print("║   Log Analiz ve Anomali Tespit Aracı v1.0║")
    print("║         github.com/Gasimoff-M            ║")
    print(f"╚══════════════════════════════════════════╝{SIFIRLA}")

    print("\n  Log kaynağını seçin:")
    print("  1 - Demo log (test için örnek veri)")
    print("  2 - Dosyadan log oku")
    secim = input("\n  Seçiminiz [1/2]: ").strip()

    analizci = LogAnalizci()

    if secim == "2":
        dosya_yolu = input("  Log dosyası yolu: ").strip()
        if not os.path.exists(dosya_yolu):
            print(f"{KIRMIZI}  [!] Dosya bulunamadı!{SIFIRLA}")
            exit()
        print(f"\n{YESIL}  [*] Log dosyası okunuyor...{SIFIRLA}")
        with open(dosya_yolu, "r", encoding="utf-8", errors="ignore") as f:
            for satir in f:
                analizci.satir_analiz_et(satir)
        analizci.anomali_tespit_et()
        analizci.rapor_yazdir(dosya_yolu)
    else:
        print(f"\n{YESIL}  [*] Demo log analiz ediliyor...{SIFIRLA}")
        demo_icerik = demo_log_olustur()
        for satir in demo_icerik.splitlines():
            analizci.satir_analiz_et(satir)
        analizci.anomali_tespit_et()
        analizci.rapor_yazdir("demo_log")
