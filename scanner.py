import logging
from pathlib import Path

log = logging.getLogger(__name__)


def find_python_files(path: Path) -> list[Path]:
    """Return all .py files under path. If path is a file, return it directly."""
    if path.is_file():
        if path.suffix == ".py":
            return [path]
        log.warning("Target is not a Python file: %s", path)
        return []
    return sorted(path.rglob("*.py"))


def read_file(path: Path) -> str | None:
    """Read file contents as text, returning None on any read error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log.warning("Could not read %s: %s", path, e)
        return None
