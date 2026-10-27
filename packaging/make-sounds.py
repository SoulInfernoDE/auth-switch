#!/usr/bin/python3
"""Synthesize the sound effects in authswitch/sounds (soft, mallet-like chimes)."""

import math
import struct
import wave
from pathlib import Path

RATE = 44100
OUT = Path(__file__).resolve().parent.parent / "authswitch" / "sounds"

# name: (length in s, [(start in s, frequency in Hz, level)])
SOUNDS = {
    "switch": (0.60, [(0.00, 659.25, 0.8), (0.09, 987.77, 1.0)]),
    "success": (0.90, [(0.00, 523.25, 0.7), (0.07, 659.25, 0.8), (0.14, 783.99, 0.9), (0.21, 1046.50, 1.0)]),
    "signout": (0.60, [(0.00, 987.77, 0.8), (0.09, 659.25, 1.0)]),
    "error": (0.55, [(0.00, 392.00, 1.0), (0.11, 311.13, 1.0)]),
}
PARTIALS = ((1, 1.0, 0.16), (2, 0.22, 0.09), (3, 0.06, 0.05))  # harmonic, level, decay time


def render(length: float, notes) -> list[float]:
    samples = [0.0] * int(length * RATE)
    for start, frequency, level in notes:
        first = int(start * RATE)
        for index in range(first, len(samples)):
            t = (index - first) / RATE
            attack = min(1.0, t / 0.006)
            samples[index] += level * attack * sum(
                gain * math.exp(-t / decay) * math.sin(2 * math.pi * frequency * harmonic * t)
                for harmonic, gain, decay in PARTIALS
            )
    fade = int(0.05 * RATE)
    for index in range(fade):
        samples[-1 - index] *= index / fade
    peak = max(abs(sample) for sample in samples)
    return [0.45 * sample / peak for sample in samples]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, (length, notes) in SOUNDS.items():
        with wave.open(str(OUT / f"{name}.wav"), "wb") as out:
            out.setnchannels(1)
            out.setsampwidth(2)
            out.setframerate(RATE)
            out.writeframes(b"".join(struct.pack("<h", int(sample * 32767)) for sample in render(length, notes)))


if __name__ == "__main__":
    main()
