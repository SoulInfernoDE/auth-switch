"""Play the bundled sound effects through whatever player the system has."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_PLAYERS = (["pw-play"], ["paplay"], ["aplay", "-q"])


def play(name: str) -> None:
    path = Path(__file__).parent / "sounds" / f"{name}.wav"
    for player in _PLAYERS:
        if shutil.which(player[0]) and path.exists():
            subprocess.Popen([*player, str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
