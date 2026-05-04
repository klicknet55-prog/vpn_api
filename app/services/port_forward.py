import sqlite3
from dataclasses import dataclass
from pathlib import Path

from app.config import DB_PATH, IPTABLES_BIN
from app.services.system import CommandError, run_command


class PortForwardError(RuntimeError):
    pass


@dataclass
class Rule:
    name: str
    protocol: str
    listen_port: int
    destination_ip: str
    destination_port: int
    created_at: str


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nat_rules (
                name TEXT PRIMARY KEY,
                protocol TEXT NOT NULL,
                listen_port INTEGER NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def list_rules() -> list[Rule]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT name, protocol, listen_port, destination_ip, destination_port, created_at
            FROM nat_rules
            ORDER BY created_at DESC
            """
        ).fetchall()

    return [Rule(*row) for row in rows]


def _run_iptables(command: list[str]) -> None:
    try:
        run_command([IPTABLES_BIN, *command], check=True)
    except CommandError as exc:
        raise PortForwardError(str(exc)) from exc


def _apply_rule(name: str, protocol: str, listen_port: int, destination_ip: str, destination_port: int) -> None:
    comment = f"vpn-api:{name}"

    _run_iptables(
        [
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            protocol,
            "--dport",
            str(listen_port),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "DNAT",
            "--to-destination",
            f"{destination_ip}:{destination_port}",
        ]
    )
    _run_iptables(
        [
            "-A",
            "FORWARD",
            "-p",
            protocol,
            "-d",
            destination_ip,
            "--dport",
            str(destination_port),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED,RELATED",
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "ACCEPT",
        ]
    )


def _delete_rule(name: str, protocol: str, listen_port: int, destination_ip: str, destination_port: int) -> None:
    comment = f"vpn-api:{name}"

    _run_iptables(
        [
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-p",
            protocol,
            "--dport",
            str(listen_port),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "DNAT",
            "--to-destination",
            f"{destination_ip}:{destination_port}",
        ]
    )
    _run_iptables(
        [
            "-D",
            "FORWARD",
            "-p",
            protocol,
            "-d",
            destination_ip,
            "--dport",
            str(destination_port),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED,RELATED",
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "ACCEPT",
        ]
    )


def create_rule(name: str, protocol: str, listen_port: int, destination_ip: str, destination_port: int) -> Rule:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT 1 FROM nat_rules WHERE name = ?", (name,)).fetchone()
        if row:
            raise PortForwardError("Nama rule sudah dipakai")

        try:
            _apply_rule(name, protocol, listen_port, destination_ip, destination_port)
            conn.execute(
                """
                INSERT INTO nat_rules (name, protocol, listen_port, destination_ip, destination_port)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, protocol, listen_port, destination_ip, destination_port),
            )
            conn.commit()
        except PortForwardError:
            conn.rollback()
            raise

        created = conn.execute(
            """
            SELECT name, protocol, listen_port, destination_ip, destination_port, created_at
            FROM nat_rules
            WHERE name = ?
            """,
            (name,),
        ).fetchone()

    if not created:
        raise PortForwardError("Rule gagal dibuat")

    return Rule(*created)


def delete_rule(name: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        proxy_table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'proxy_routes'"
        ).fetchone()
        if proxy_table_exists:
            used_by_proxy = conn.execute(
                "SELECT 1 FROM proxy_routes WHERE port_forward_name = ? LIMIT 1",
                (name,),
            ).fetchone()
            if used_by_proxy:
                raise PortForwardError("Rule masih dipakai proxy route, hapus proxy route dulu")

        row = conn.execute(
            """
            SELECT name, protocol, listen_port, destination_ip, destination_port
            FROM nat_rules
            WHERE name = ?
            """,
            (name,),
        ).fetchone()
        if not row:
            raise PortForwardError("Rule tidak ditemukan")

        try:
            _delete_rule(*row)
            conn.execute("DELETE FROM nat_rules WHERE name = ?", (name,))
            conn.commit()
        except PortForwardError:
            conn.rollback()
            raise
