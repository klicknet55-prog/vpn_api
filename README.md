# VPN API Management

API untuk manajemen L2TP/IPsec (Libreswan) di Ubuntu 24.04.4.

Fitur:
- Create user + password + IP static
- Disable akun user
- Enable akun user
- Delete akun user
- Disconnect akun user (best effort berdasarkan proses pppd dari log xl2tpd)
- Create port forwarding NAT
- Delete port forwarding NAT
- Create subdomain proxy ke rule port forwarding terpilih
- Auto install SSL Let's Encrypt untuk subdomain proxy
- Opsional auto create/delete A record subdomain via BIND9 (nsupdate)

## Arsitektur

- User VPN disimpan pada file `/etc/ppp/chap-secrets`
- Rule NAT dikelola dengan `iptables`
- Metadata NAT disimpan pada SQLite: `/var/lib/vpn-api-manager/rules.db`
- API dibangun dengan FastAPI

## Persiapan Ubuntu 24.04.4

Jalankan sebagai root:

```bash
apt update
apt install -y python3 python3-venv python3-pip iptables iproute2 apache2 certbot python3-certbot-apache bind9-dnsutils
a2enmod proxy proxy_http headers rewrite ssl
systemctl restart apache2
mkdir -p /opt/vpn_api
```

Salin source ini ke `/opt/vpn_api`, lalu:

```bash
cd /opt/vpn_api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Buat file `.env` untuk kredensial Basic Auth:

```bash
cp /opt/vpn_api/.env.example /opt/vpn_api/.env
nano /opt/vpn_api/.env
```

Isi:

```env
API_USERNAME=admin
API_PASSWORD=passwordkuat123
PROXY_BASE_DOMAIN=example.com
LETSENCRYPT_EMAIL=admin@example.com

# Opsional BIND9 (aktifkan true jika ingin API auto create A record)
BIND9_AUTO_A_RECORD=false
BIND9_ZONE=example.com
BIND9_SERVER=127.0.0.1
BIND9_KEY_PATH=/etc/bind/keys/vpn-api.key
BIND9_A_TARGET_IP=203.0.113.10
BIND9_TTL=300
```

Jika `BIND9_AUTO_A_RECORD=true`, endpoint create/delete proxy route akan otomatis menambah/menghapus A record subdomain via `nsupdate`.
Pastikan key TSIG untuk `nsupdate` sudah diizinkan pada zone BIND9.

### Contoh konfigurasi untuk server ini

```env
PROXY_BASE_DOMAIN=klickerz.my.id
LETSENCRYPT_EMAIL=klicknet55@gmail.com
BIND9_AUTO_A_RECORD=true
BIND9_ZONE=klickerz.my.id
BIND9_SERVER=116.251.216.196
BIND9_KEY_PATH=/etc/bind/keys/vpn-api.key
BIND9_A_TARGET_IP=116.251.216.196
BIND9_TTL=300
```

Nilai `BIND9_KEY_PATH=/path/ke/key-tsig.key` yang Anda kirim masih placeholder. Untuk implementasi nyata, saya sarankan path seperti `/etc/bind/keys/vpn-api.key`.

### Contoh setup TSIG untuk BIND9

Buat key TSIG:

```bash
install -d -m 700 /etc/bind/keys
tsig-keygen -a hmac-sha256 vpn-api-update > /etc/bind/keys/vpn-api.key
chmod 600 /etc/bind/keys/vpn-api.key
```

Contoh isi key yang di-generate akan mirip seperti ini:

```conf
key "vpn-api-update" {
  algorithm hmac-sha256;
  secret "GANTI_DENGAN_SECRET_GENERATED";
};
```

Include key di konfigurasi BIND9, misalnya di `named.conf.local`:

```conf
include "/etc/bind/keys/vpn-api.key";

zone "klickerz.my.id" {
  type master;
  file "/etc/bind/db.klickerz.my.id";
  update-policy {
    grant vpn-api-update zonesub ANY;
  };
};
```

Jika Anda ingin lebih ketat hanya untuk A record, gunakan policy yang lebih sempit sesuai kebutuhan operasional zone Anda.

Setelah itu reload BIND9:

```bash
named-checkconf
systemctl reload bind9
systemctl status bind9
```

Terakhir, isi `.env` aplikasi dengan nilai yang sama dan restart service API:

```bash
systemctl restart vpn-api
systemctl status vpn-api
```

## Menjalankan API

```bash
cd /opt/vpn_api
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Dokumentasi Swagger:
- `http://SERVER_IP:8080/docs`

## Endpoint

1) Create user password ip

```bash
curl -X POST http://127.0.0.1:8080/users \
  -u admin:passwordkuat123 \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"pass1234","ip":"10.10.10.10"}'
```

2) Disable akun user

```bash
curl -X POST http://127.0.0.1:8080/users/user1/disable \
  -u admin:passwordkuat123
```

3) Enable akun user

```bash
curl -X POST http://127.0.0.1:8080/users/user1/enable \
  -u admin:passwordkuat123
```

4) Delete akun user

```bash
curl -X DELETE http://127.0.0.1:8080/users/user1 \
  -u admin:passwordkuat123
```

5) Disconnect akun user

```bash
curl -X POST http://127.0.0.1:8080/users/user1/disconnect \
  -u admin:passwordkuat123
```

6) Create portforwarding NAT

```bash
curl -X POST http://127.0.0.1:8080/port-forwardings \
  -u admin:passwordkuat123 \
  -H "Content-Type: application/json" \
  -d '{
    "name":"web-1",
    "protocol":"tcp",
    "listen_port":8081,
    "destination_ip":"10.10.10.2",
    "destination_port":80
  }'
```

7) Delete portforwarding NAT

```bash
curl -X DELETE http://127.0.0.1:8080/port-forwardings/web-1 \
  -u admin:passwordkuat123
```

8) Create proxy subdomain + SSL dari port forwarding terpilih

```bash
curl -X POST http://127.0.0.1:8080/proxy-routes \
  -u admin:passwordkuat123 \
  -H "Content-Type: application/json" \
  -d '{
    "name":"app-user1",
    "subdomain":"user1",
    "port_forward_name":"web-1"
  }'
```

9) Cek subdomain tersedia (DB + DNS BIND9)

```bash
curl -X GET http://127.0.0.1:8080/proxy-routes/check-subdomain/user1 \
  -u admin:passwordkuat123
```

10) List proxy route

```bash
curl -X GET http://127.0.0.1:8080/proxy-routes \
  -u admin:passwordkuat123
```

11) Delete proxy route

```bash
curl -X DELETE http://127.0.0.1:8080/proxy-routes/app-user1 \
  -u admin:passwordkuat123
```

## Menjalankan sebagai systemd

Buat file `/etc/systemd/system/vpn-api.service`:

```ini
[Unit]
Description=VPN API Management
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/vpn_api
ExecStart=/opt/vpn_api/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Aktifkan service:

```bash
systemctl daemon-reload
systemctl enable --now vpn-api
systemctl status vpn-api
```

## Catatan penting

- API ini harus dijalankan sebagai root agar bisa mengubah `chap-secrets`, membaca journal, dan mengelola `iptables`.
- Fitur disconnect bersifat best effort karena sesi L2TP-PPP tidak selalu menyimpan mapping username secara konsisten pada semua konfigurasi.
- Jika server memakai `nftables` murni, sesuaikan implementasi NAT ke `nft`.

## Integrasi Basic Auth di Aplikasi Web

Semua endpoint dilindungi HTTP Basic Auth. Header `Authorization` wajib dikirim di setiap request.

### Format header
```
Authorization: Basic <base64(username:password)>
```

### Contoh integrasi JavaScript (fetch)
```js
const API_BASE = "http://192.168.56.10:8080";
const credentials = btoa("admin:passwordkuat123"); // base64

async function createUser(username, password, ip) {
  const res = await fetch(`${API_BASE}/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Basic ${credentials}`,
    },
    body: JSON.stringify({ username, password, ip }),
  });
  return res.json();
}

async function disableUser(username) {
  const res = await fetch(`${API_BASE}/users/${username}/disable`, {
    method: "POST",
    headers: { "Authorization": `Basic ${credentials}` },
  });
  return res.json();
}

async function deleteUser(username) {
  const res = await fetch(`${API_BASE}/users/${username}`, {
    method: "DELETE",
    headers: { "Authorization": `Basic ${credentials}` },
  });
  return res.json();
}
```

### Contoh integrasi PHP (cURL)
```php
<?php
$api = "http://192.168.56.10:8080";
$user = "admin";
$pass = "passwordkuat123";

function apiRequest(string $method, string $path, ?array $body = null): array {
    global $api, $user, $pass;
    $ch = curl_init("$api$path");
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_USERPWD, "$user:$pass");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    if ($body) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    }
    $result = curl_exec($ch);
    curl_close($ch);
    return json_decode($result, true);
}

// Buat user
$response = apiRequest("POST", "/users", [
    "username" => "user1",
    "password" => "pass1234",
    "ip"       => "10.10.10.10",
]);

// Disable user
$response = apiRequest("POST", "/users/user1/disable");
?>
```

### Keamanan tambahan yang disarankan
- Jalankan API di belakang **HTTPS** (Apache + Let's Encrypt) agar Basic Auth tidak dikirim plaintext.
- Simpan kredensial di environment variable atau secret manager, **jangan hardcode** di kode frontend.
- Untuk produksi, pertimbangkan ganti Basic Auth dengan **API Key** atau **JWT**.


<!-- Security scan triggered at 2026-08-31 17:17:21 -->

<!-- Security scan triggered at 2026-08-31 16:54:18 -->

<!-- Security scan triggered at 2026-09-02 06:51:39 -->