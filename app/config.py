import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

CHAP_SECRETS_PATH = Path("/etc/ppp/chap-secrets")
DB_PATH = Path("/var/lib/vpn-api-manager/rules.db")

IPTABLES_BIN = "iptables"
SYSTEMCTL_BIN = "systemctl"
JOURNALCTL_BIN = "journalctl"

# To avoid writing malformed usernames into chap-secrets.
USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]{3,32}$"

# Basic Auth credentials — wajib diset via environment variable atau file .env
API_USERNAME: str = os.environ.get("API_USERNAME", "")
API_PASSWORD: str = os.environ.get("API_PASSWORD", "")
