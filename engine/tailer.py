import os
import time
from pathlib import Path
from typing import Callable, Iterable

class LogTailer:
    """
    Monitoriza múltiplos ficheiros de log em tempo real (equivalente a tail -F),
    detetando rotação de logs (mudança de inode ou truncagem) sem perder eventos.
    """

    def __init__(self, file_paths: Iterable[str], poll_interval: float = 0.25):
        self.paths = [Path(p) for p in file_paths]
        self.poll_interval = poll_interval
        self._handles: dict[Path, tuple[object, int]] = {}

    def _sync_handles(self, from_end: bool = False) -> None:
        for path in self.paths:
            if not path.exists():
                continue
            stat = path.stat()
            current = self._handles.get(path)

            if current is None:
                fh = open(path, "r", encoding="utf-8", errors="replace")
                if from_end:
                    fh.seek(0, os.SEEK_END)
                self._handles[path] = (fh, stat.st_ino)
            else:
                fh, old_ino = current
                # Deteta rotação por rename/create (novo inode) ou truncagem (copytruncate)
                if stat.st_ino != old_ino or stat.st_size < fh.tell():
                    fh.close()
                    new_fh = open(path, "r", encoding="utf-8", errors="replace")
                    self._handles[path] = (new_fh, stat.st_ino)

    def follow(
        self,
        on_line: Callable[[str, Path], None],
        tick_callback: Callable[[], None] | None = None,
        from_end: bool = True,
    ) -> None:
        self._sync_handles(from_end=from_end)
        try:
            while True:
                self._sync_handles(from_end=False)
                had_data = False
                for path, (fh, _) in list(self._handles.items()):
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
            for fh, _ in self._handles.values():
                fh.close()
