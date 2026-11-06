"""Habilita la importación del paquete `core` en pytest (raíz del repo en sys.path)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
