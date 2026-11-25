import logging
import os
import time
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("homelab-auditor.tailer")


class LogTailer:
    """
    Continuous multi-file log follower (tail -F semantics) resilient to
    copytruncate and inode-replacement log rotation.
    """

    def __init__(self, file_paths: list[str], poll_interval: float = 0.25):
        self.paths = [Path(p) for p in file_paths]
        self.poll_interval = poll_interval
        self._running = False
        self._handles: dict[Path, object] = {}
        self._inodes: dict[Path, int] = {}

    def stop(self) -> None:
        self._running = False

    def _open_file(self, path: Path, from_end: bool = True) -> None:
        if not path.exists():
            return
        try:
            fh = path.open("r", encoding="utf-8", errors="replace")
            if from_end:
                fh.seek(0, os.SEEK_END)
            self._handles[path] = fh
            self._inodes[path] = path.stat().st_ino
        except OSError as exc:
            logger.debug(f"Could not open log file '{path}': {exc}")

    def follow(
        self,
        on_line: Callable[[str, Path], None],
        tick_callback: Optional[Callable[[], None]] = None,
        from_end: bool = True,
    ) -> None:
        for path in self.paths:
            self._open_file(path, from_end=from_end)

        self._running = True
        try:
            while self._running:
                for path in self.paths:
                    if not path.exists():
                        if path in self._handles:
                            self._handles[path].close()
                            del self._handles[path]
                            self._inodes.pop(path, None)
                        continue

                    if path not in self._handles:
                        self._open_file(path, from_end=False)
                        if path not in self._handles:
                            continue

                    fh = self._handles[path]
                    try:
                        stat = path.stat()
                        if stat.st_ino != self._inodes.get(path) or stat.st_size < fh.tell():
                            fh.close()
                            self._open_file(path, from_end=False)
                            fh = self._handles[path]
                    except OSError:
                        continue

                    while self._running:
                        line = fh.readline()
                        if not line:
                            break
                        on_line(line, path)

                if tick_callback:
                    tick_callback()
                time.sleep(self.poll_interval)
        finally:
            for fh in self._handles.values():
                try:
                    fh.close()
                except OSError:
                    pass
            self._handles.clear()
