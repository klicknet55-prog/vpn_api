import shlex
import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


class CommandError(RuntimeError):
    pass


def run_command(command: Sequence[str], check: bool = True) -> CommandResult:
    proc = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
    )
    result = CommandResult(
        stdout=(proc.stdout or "").strip(),
        stderr=(proc.stderr or "").strip(),
        returncode=proc.returncode,
    )
    if check and proc.returncode != 0:
        pretty = " ".join(shlex.quote(c) for c in command)
        raise CommandError(
            f"Command failed ({proc.returncode}): {pretty}; stderr: {result.stderr}"
        )
    return result
