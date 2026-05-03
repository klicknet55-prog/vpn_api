import os
import re
import signal
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import NamedTemporaryFile

from app.config import CHAP_SECRETS_PATH, JOURNALCTL_BIN, USERNAME_PATTERN
from app.services.system import CommandError, run_command


class UserServiceError(RuntimeError):
    pass


def _validate_username(username: str) -> None:
    if not re.fullmatch(USERNAME_PATTERN, username):
        raise UserServiceError("Username tidak valid. Gunakan 3-32 karakter: a-z, A-Z, 0-9, _, ., -")


def _validate_static_ip(ip: str) -> str:
    try:
        return str(IPv4Address(ip))
    except ValueError as exc:
        raise UserServiceError("IP static tidak valid") from exc


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        raise UserServiceError(f"File tidak ditemukan: {path}")
    return path.read_text(encoding="utf-8").splitlines()


def _atomic_write(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=path.parent) as tmp:
        tmp.write("\n".join(lines).rstrip() + "\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def create_user(username: str, password: str, ip: str) -> None:
    _validate_username(username)
    if any(char.isspace() for char in password):
        raise UserServiceError("Password tidak boleh mengandung spasi")
    static_ip = _validate_static_ip(ip)

    lines = _read_lines(CHAP_SECRETS_PATH)
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts and parts[0] == username:
            raise UserServiceError("User sudah ada")

    lines.append(f'{username} l2tpd "{password}" {static_ip}')
    _atomic_write(CHAP_SECRETS_PATH, lines)


def delete_user(username: str) -> None:
    _validate_username(username)
    lines = _read_lines(CHAP_SECRETS_PATH)

    kept: list[str] = []
    removed = False
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            parts = stripped.split()
            if parts and parts[0] == username:
                removed = True
                continue
        kept.append(line)

    if not removed:
        raise UserServiceError("User tidak ditemukan")

    _atomic_write(CHAP_SECRETS_PATH, kept)


def disable_user(username: str) -> None:
    _validate_username(username)
    lines = _read_lines(CHAP_SECRETS_PATH)

    found_active = False
    found_disabled = False
    updated: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            updated.append(line)
            continue

        if stripped.startswith("#"):
            uncommented = stripped.lstrip("#").strip()
            parts = uncommented.split()
            if parts and parts[0] == username:
                found_disabled = True
            updated.append(line)
            continue

        parts = stripped.split()
        if parts and parts[0] == username:
            found_active = True
            updated.append(f"# disabled {stripped}")
            continue

        updated.append(line)

    if not found_active:
        if found_disabled:
            raise UserServiceError("User sudah disabled")
        raise UserServiceError("User tidak ditemukan")

    _atomic_write(CHAP_SECRETS_PATH, updated)

    # Best effort: after disabling credentials, terminate active sessions immediately.
    try:
        disconnect_user(username)
    except UserServiceError:
        pass


def enable_user(username: str) -> None:
    _validate_username(username)
    lines = _read_lines(CHAP_SECRETS_PATH)

    found_active = False
    found_disabled = False
    updated: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            updated.append(line)
            continue

        if stripped.startswith("# disabled "):
            uncommented = stripped[len("# disabled ") :].strip()
            parts = uncommented.split()
            if parts and parts[0] == username:
                found_disabled = True
                updated.append(uncommented)
                continue
            updated.append(line)
            continue

        if not stripped.startswith("#"):
            parts = stripped.split()
            if parts and parts[0] == username:
                found_active = True

        updated.append(line)

    if not found_disabled:
        if found_active:
            raise UserServiceError("User sudah aktif")
        raise UserServiceError("User tidak ditemukan")

    _atomic_write(CHAP_SECRETS_PATH, updated)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _get_user_static_ip(username: str) -> str | None:
    lines = _read_lines(CHAP_SECRETS_PATH)
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        if parts[0] == username:
            return parts[3]
    return None


def disconnect_user(username: str) -> int:
    _validate_username(username)

    try:
        logs = run_command(
            [
                JOURNALCTL_BIN,
                "-u",
                "xl2tpd",
                "--since",
                "-2d",
                "--no-pager",
            ],
            check=True,
        ).stdout.splitlines()
    except CommandError:
        logs = []

    pid_to_user: dict[int, str] = {}
    auth_patterns = [
        re.compile(r"pppd\[(\d+)\]:.*authorized as (\S+)", re.IGNORECASE),
        re.compile(r"pppd\[(\d+)\]:.*CHAP peer authentication succeeded for (\S+)", re.IGNORECASE),
        re.compile(r"pppd\[(\d+)\]:.*Peer\s+(\S+)\s+authenticated", re.IGNORECASE),
        re.compile(r"pppd\[(\d+)\]:.*authenticating\s+(\S+)", re.IGNORECASE),
        re.compile(r"pppd\[(\d+)\]:.*CHAP Response .*name\s*=\s*\"([^\"]+)\"", re.IGNORECASE),
    ]

    for line in logs:
        for pattern in auth_patterns:
            m = pattern.search(line)
            if not m:
                continue
            # Strip quotes/trailing punctuation from username tokens in syslog lines.
            parsed_user = m.group(2).strip('"\'.,:;()[]{}<>')
            pid_to_user[int(m.group(1))] = parsed_user
            break

    target_pids = [pid for pid, user in pid_to_user.items() if user == username and _pid_alive(pid)]

    if not target_pids:
        static_ip = _get_user_static_ip(username)
        if static_ip:
            try:
                ps_lines = run_command(["ps", "-eo", "pid,args"], check=True).stdout.splitlines()
            except CommandError:
                ps_lines = []

            remote_ip_re = re.compile(rf":{re.escape(static_ip)}(?:\s|$)")
            matched_pids: set[int] = set()
            for line in ps_lines:
                m = re.match(r"\s*(\d+)\s+(.*)", line)
                if not m:
                    continue
                pid = int(m.group(1))
                args = m.group(2)
                if "pppd" not in args:
                    continue
                if not remote_ip_re.search(args):
                    continue
                if _pid_alive(pid):
                    matched_pids.add(pid)

            target_pids = sorted(matched_pids)

    disconnected = 0
    for pid in target_pids:
        try:
            os.kill(pid, signal.SIGTERM)
            disconnected += 1
        except OSError:
            continue

    return disconnected
