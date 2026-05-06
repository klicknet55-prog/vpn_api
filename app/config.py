import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

CHAP_SECRETS_PATH = Path("/etc/ppp/chap-secrets")
DB_PATH = Path("/var/lib/vpn-api-manager/rules.db")
APACHE_SITES_AVAILABLE_PATH = Path("/etc/apache2/sites-available")
APACHE_SITES_ENABLED_PATH = Path("/etc/apache2/sites-enabled")

IPTABLES_BIN = "iptables"
IPTABLES_SAVE_BIN = "iptables-save"
SYSTEMCTL_BIN = "systemctl"
JOURNALCTL_BIN = "journalctl"
APACHECTL_BIN = "apache2ctl"
A2ENSITE_BIN = "a2ensite"
A2DISSITE_BIN = "a2dissite"
A2ENMOD_BIN = "a2enmod"
CERTBOT_BIN = "certbot"
NSUPDATE_BIN = "nsupdate"
DIG_BIN = "dig"

# To avoid writing malformed usernames into chap-secrets.
USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]{3,32}$"

# Basic Auth credentials — wajib diset via environment variable atau file .env
API_USERNAME: str = os.environ.get("API_USERNAME", "")
API_PASSWORD: str = os.environ.get("API_PASSWORD", "")

# Domain induk untuk fitur subdomain proxy.
PROXY_BASE_DOMAIN: str = os.environ.get("PROXY_BASE_DOMAIN", "")

# Email untuk registrasi Let's Encrypt.
LETSENCRYPT_EMAIL: str = os.environ.get("LETSENCRYPT_EMAIL", "")

# Integrasi DNS BIND9 (opsional) untuk auto create/delete A record subdomain.
BIND9_AUTO_A_RECORD: bool = os.environ.get("BIND9_AUTO_A_RECORD", "false").lower() in ("1", "true", "yes", "on")
BIND9_ZONE: str = os.environ.get("BIND9_ZONE", "")
BIND9_SERVER: str = os.environ.get("BIND9_SERVER", "")
BIND9_KEY_PATH: str = os.environ.get("BIND9_KEY_PATH", "")
BIND9_A_TARGET_IP: str = os.environ.get("BIND9_A_TARGET_IP", "")
BIND9_TTL: int = int(os.environ.get("BIND9_TTL", "300"))
