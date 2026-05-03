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

## Arsitektur

- User VPN disimpan pada file `/etc/ppp/chap-secrets`
- Rule NAT dikelola dengan `iptables`
- Metadata NAT disimpan pada SQLite: `/var/lib/vpn-api-manager/rules.db`
- API dibangun dengan FastAPI

## Persiapan Ubuntu 24.04.4

Jalankan sebagai root:

```bash
apt update
apt install -y python3 python3-venv python3-pip iptables iproute2
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
- Jalankan API di belakang **HTTPS** (Nginx + Let's Encrypt) agar Basic Auth tidak dikirim plaintext.
- Simpan kredensial di environment variable atau secret manager, **jangan hardcode** di kode frontend.
- Untuk produksi, pertimbangkan ganti Basic Auth dengan **API Key** atau **JWT**.
