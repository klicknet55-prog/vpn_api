import sqlite3
import tempfile
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

from app.config import (
    A2DISSITE_BIN,
    A2ENMOD_BIN,
    A2ENSITE_BIN,
    APACHECTL_BIN,
    APACHE_SITES_AVAILABLE_PATH,
    APACHE_SITES_ENABLED_PATH,
    BIND9_A_TARGET_IP,
    BIND9_AUTO_A_RECORD,
    BIND9_KEY_PATH,
    BIND9_SERVER,
    BIND9_TTL,
    BIND9_ZONE,
    CERTBOT_BIN,
    DB_PATH,
    DIG_BIN,
    LETSENCRYPT_EMAIL,
    NSUPDATE_BIN,
    PROXY_BASE_DOMAIN,
    SYSTEMCTL_BIN,
)
from app.services.system import CommandError, run_command


class ProxyError(RuntimeError):
    pass


@dataclass
class ProxyRoute:
    name: str
    subdomain: str
    domain: str
    port_forward_name: str
    upstream_ip: str
    upstream_port: int
    ssl_enabled: int
    created_at: str


@dataclass
class SubdomainCheck:
    subdomain: str
    domain: str
    available: bool
    exists_in_db: bool
    exists_in_dns: bool
    dns_checked: bool
    dns_records: list[str]
    reason: str


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_routes (
                name TEXT PRIMARY KEY,
                subdomain TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL UNIQUE,
                port_forward_name TEXT NOT NULL,
                upstream_ip TEXT NOT NULL,
                upstream_port INTEGER NOT NULL,
                ssl_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (port_forward_name) REFERENCES nat_rules(name)
            )
            """
        )
        conn.commit()


def _run(command: list[str]) -> None:
    try:
        run_command(command, check=True)
    except CommandError as exc:
        raise ProxyError(str(exc)) from exc


def _run_result(command: list[str], check: bool = True):
    try:
        return run_command(command, check=check)
    except CommandError as exc:
        raise ProxyError(str(exc)) from exc


def _conf_name(name: str) -> str:
    return f"vpn-api-proxy-{name}.conf"


def _ssl_conf_name(name: str) -> str:
    return f"vpn-api-proxy-{name}-le-ssl.conf"


def _available_conf_path(name: str) -> Path:
    return APACHE_SITES_AVAILABLE_PATH / _conf_name(name)


def _enabled_conf_path(name: str) -> Path:
    return APACHE_SITES_ENABLED_PATH / _conf_name(name)


def _available_conf_path_by_conf(conf_name: str) -> Path:
    return APACHE_SITES_AVAILABLE_PATH / conf_name


def _enabled_conf_path_by_conf(conf_name: str) -> Path:
    return APACHE_SITES_ENABLED_PATH / conf_name


def _disable_and_remove_site(conf_name: str) -> None:
    available = _available_conf_path_by_conf(conf_name)
    enabled = _enabled_conf_path_by_conf(conf_name)

    if enabled.exists() or enabled.is_symlink():
        _run([A2DISSITE_BIN, "-q", conf_name])
        enabled.unlink(missing_ok=True)
    if available.exists():
        available.unlink(missing_ok=True)


def _domain_from_subdomain(subdomain: str) -> str:
    if not PROXY_BASE_DOMAIN:
        raise ProxyError("PROXY_BASE_DOMAIN belum diset")
    return f"{subdomain}.{PROXY_BASE_DOMAIN}"


def _dns_a_records(domain: str) -> tuple[bool, list[str]]:
    command = [DIG_BIN]
    if BIND9_SERVER:
        command.append(f"@{BIND9_SERVER}")
    command.extend(["+short", domain, "A"])

    result = _run_result(command, check=False)
    if result.returncode != 0:
        raise ProxyError(f"Gagal query DNS BIND9 untuk {domain}: {result.stderr}")

    records: list[str] = []
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            parsed = ip_address(candidate)
        except ValueError:
            continue
        if parsed.version == 4:
            records.append(str(parsed))

    return True, records


def check_subdomain_availability(subdomain: str) -> SubdomainCheck:
    domain = _domain_from_subdomain(subdomain)

    with sqlite3.connect(DB_PATH) as conn:
        in_db = conn.execute(
            "SELECT 1 FROM proxy_routes WHERE subdomain = ? OR domain = ? LIMIT 1",
            (subdomain, domain),
        ).fetchone() is not None

    dns_checked = False
    dns_records: list[str] = []
    reason = "Tersedia"

    try:
        dns_checked, dns_records = _dns_a_records(domain)
    except ProxyError as exc:
        reason = f"Gagal cek DNS: {exc}"

    in_dns = len(dns_records) > 0

    if in_db:
        reason = "Subdomain sudah dipakai di database"
    elif in_dns:
        reason = "Subdomain sudah punya A record di DNS"
    elif not dns_checked:
        reason = "DNS tidak bisa diverifikasi"

    available = (not in_db) and (not in_dns) and dns_checked

    return SubdomainCheck(
        subdomain=subdomain,
        domain=domain,
        available=available,
        exists_in_db=in_db,
        exists_in_dns=in_dns,
        dns_checked=dns_checked,
        dns_records=dns_records,
        reason=reason,
    )


def _validate_ssl_config() -> None:
    if not LETSENCRYPT_EMAIL:
        raise ProxyError("LETSENCRYPT_EMAIL belum diset")


def _validate_bind9_config() -> None:
    if not BIND9_ZONE:
        raise ProxyError("BIND9_ZONE belum diset")
    if not BIND9_A_TARGET_IP:
        raise ProxyError("BIND9_A_TARGET_IP belum diset")


def _nsupdate(commands: list[str]) -> None:
    cmd = [NSUPDATE_BIN]
    if BIND9_KEY_PATH:
        cmd.extend(["-k", BIND9_KEY_PATH])

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write("\n".join(commands) + "\n")
        tmp_path = tmp.name

    try:
        _run([*cmd, tmp_path])
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _to_fqdn(value: str) -> str:
    return value if value.endswith(".") else f"{value}."


def _ensure_dns_a_record(domain: str) -> None:
    if not BIND9_AUTO_A_RECORD:
        return

    _validate_bind9_config()
    fqdn = _to_fqdn(domain)
    zone = _to_fqdn(BIND9_ZONE)
    server_line = [f"server {BIND9_SERVER}"] if BIND9_SERVER else []
    _nsupdate(
        [
            *server_line,
            f"zone {zone}",
            f"update delete {fqdn} A",
            f"update add {fqdn} {BIND9_TTL} A {BIND9_A_TARGET_IP}",
            "send",
        ]
    )


def _delete_dns_a_record(domain: str) -> None:
    if not BIND9_AUTO_A_RECORD:
        return

    _validate_bind9_config()
    fqdn = _to_fqdn(domain)
    zone = _to_fqdn(BIND9_ZONE)
    server_line = [f"server {BIND9_SERVER}"] if BIND9_SERVER else []
    _nsupdate(
        [
            *server_line,
            f"zone {zone}",
            f"update delete {fqdn} A",
            "send",
        ]
    )


def _delete_certificate(domain: str) -> None:
    try:
        _run([CERTBOT_BIN, "delete", "--cert-name", domain, "--non-interactive"])
    except ProxyError as exc:
        message = str(exc).lower()
        if "no certificate found" in message or "does not exist" in message:
            return
        raise


def _apache_template(domain: str, upstream_ip: str, upstream_port: int) -> str:
    return (
        f"<VirtualHost *:80>\n"
        f"    ServerName {domain}\n"
        "\n"
        "    ProxyPreserveHost On\n"
        f"    ProxyPass / http://{upstream_ip}:{upstream_port}/\n"
        f"    ProxyPassReverse / http://{upstream_ip}:{upstream_port}/\n"
        "\n"
        "    RequestHeader set X-Forwarded-Proto \"expr=%{REQUEST_SCHEME}\"\n"
        "    RequestHeader set X-Forwarded-Port \"expr=%{SERVER_PORT}\"\n"
        "</VirtualHost>\n"
    )


def _configure_proxy(name: str, domain: str, upstream_ip: str, upstream_port: int) -> None:
    APACHE_SITES_AVAILABLE_PATH.mkdir(parents=True, exist_ok=True)
    APACHE_SITES_ENABLED_PATH.mkdir(parents=True, exist_ok=True)

    available = _available_conf_path(name)
    enabled = _enabled_conf_path(name)
    conf_name = _conf_name(name)
    available.write_text(_apache_template(domain, upstream_ip, upstream_port), encoding="utf-8")

    try:
        _run([A2ENMOD_BIN, "proxy"])
        _run([A2ENMOD_BIN, "proxy_http"])
        _run([A2ENMOD_BIN, "headers"])
        _run([A2ENMOD_BIN, "rewrite"])
        _run([A2ENMOD_BIN, "ssl"])
        _run([A2ENSITE_BIN, conf_name])
        _run([APACHECTL_BIN, "-t"])
        _run([SYSTEMCTL_BIN, "reload", "apache2"])
        _run(
            [
                CERTBOT_BIN,
                "--apache",
                "-d",
                domain,
                "--redirect",
                "--non-interactive",
                "--agree-tos",
                "-m",
                LETSENCRYPT_EMAIL,
            ]
        )
        _run([APACHECTL_BIN, "-t"])
        _run([SYSTEMCTL_BIN, "reload", "apache2"])
    except ProxyError:
        try:
            _delete_certificate(domain)
        except ProxyError:
            pass

        for candidate in (conf_name, _ssl_conf_name(name)):
            try:
                _disable_and_remove_site(candidate)
            except ProxyError:
                pass

        if available.exists():
            available.unlink(missing_ok=True)
        try:
            _run([APACHECTL_BIN, "-t"])
            _run([SYSTEMCTL_BIN, "reload", "apache2"])
        except ProxyError:
            pass
        raise


def _remove_proxy(name: str, domain: str) -> None:
    _delete_certificate(domain)

    for candidate in (_conf_name(name), _ssl_conf_name(name)):
        _disable_and_remove_site(candidate)

    _run([APACHECTL_BIN, "-t"])
    _run([SYSTEMCTL_BIN, "reload", "apache2"])


def list_routes() -> list[ProxyRoute]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT name, subdomain, domain, port_forward_name, upstream_ip, upstream_port, ssl_enabled, created_at
            FROM proxy_routes
            ORDER BY created_at DESC
            """
        ).fetchall()

    return [ProxyRoute(*row) for row in rows]


def create_route(name: str, subdomain: str, port_forward_name: str) -> ProxyRoute:
    _validate_ssl_config()
    check = check_subdomain_availability(subdomain)
    if not check.available:
        raise ProxyError(f"Subdomain tidak tersedia: {check.reason}")

    domain = check.domain
    dns_created = False

    with sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute("SELECT 1 FROM proxy_routes WHERE name = ?", (name,)).fetchone()
        if existing:
            raise ProxyError("Nama proxy route sudah dipakai")

        forward_row = conn.execute(
            """
            SELECT protocol, destination_ip, destination_port
            FROM nat_rules
            WHERE name = ?
            """,
            (port_forward_name,),
        ).fetchone()
        if not forward_row:
            raise ProxyError("Port forwarding tidak ditemukan")

        protocol, destination_ip, destination_port = forward_row
        if protocol != "tcp":
            raise ProxyError("Proxy domain hanya mendukung port forwarding protocol tcp")

        _ensure_dns_a_record(domain)
        dns_created = True

        try:
            _configure_proxy(
                name=name,
                domain=domain,
                upstream_ip=destination_ip,
                upstream_port=destination_port,
            )
        except ProxyError:
            if dns_created:
                try:
                    _delete_dns_a_record(domain)
                except ProxyError:
                    pass
            raise

        try:
            conn.execute(
                """
                INSERT INTO proxy_routes (name, subdomain, domain, port_forward_name, upstream_ip, upstream_port, ssl_enabled)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (name, subdomain, domain, port_forward_name, destination_ip, destination_port),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            _remove_proxy(name, domain)
            if dns_created:
                try:
                    _delete_dns_a_record(domain)
                except ProxyError:
                    pass
            raise ProxyError("Subdomain atau nama proxy sudah dipakai") from exc

        created = conn.execute(
            """
            SELECT name, subdomain, domain, port_forward_name, upstream_ip, upstream_port, ssl_enabled, created_at
            FROM proxy_routes
            WHERE name = ?
            """,
            (name,),
        ).fetchone()

    if not created:
        raise ProxyError("Proxy route gagal dibuat")

    return ProxyRoute(*created)


def delete_route(name: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT name, domain FROM proxy_routes WHERE name = ?", (name,)).fetchone()
        if not row:
            raise ProxyError("Proxy route tidak ditemukan")

        _, domain = row
        _delete_dns_a_record(domain)
        _remove_proxy(name, domain)
        conn.execute("DELETE FROM proxy_routes WHERE name = ?", (name,))
        conn.commit()
