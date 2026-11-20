import os
import time
from pathlib import Path
from typing import Callable, Iterable

class LogTailer:
    """
    Monitoriza múltiplos ficheiros de log em tempo real, encaminhando
    novas linhas para um callback de inspeção.
    """

    def __init__(self, file_paths: Iterable[str], poll_interval: float = 0.25):
        self.paths = [Path(p) for p in file_paths]
        self.poll_interval = poll_interval
        self._handles: dict[Path, object] = {}

    def _open_files(self, from_end: bool = True) -> None:
        for path in self.paths:
            if path in self._handles or not path.exists():
                continue
            fh = open(path, "r", encoding="utf-8", errors="replace")
            if from_end:
                fh.seek(0, os.SEEK_END)
            self._handles[path] = fh

    def follow(self, on_line: Callable[[str, Path], None], tick_callback: Callable[[], None] | None = None, from_end: bool = True) -> None:
        self._open_files(from_end=from_end)
        try:
            while True:
                had_data = False
                for path, fh in list(self._handles.items()):
                    line = fh.readline()
                    while line:
                        had_data = True
                        on_line(line, path)
                        line = fh.readline()

                if tick_callback:
                    tick_callback()

                if not had_data:
                    time.sleep(self.poll_interval)
        finally:
            for fh in self._handles.values():
                fh.close()
