"""이미 분석한 위협 ID 를 파일에 저장해 재시작 후에도 중복 분석을 막습니다."""

from __future__ import annotations

import json
import logging
import os
from collections import OrderedDict
from pathlib import Path

log = logging.getLogger(__name__)


class SeenThreats:
    def __init__(self, path: str = "", max_size: int = 10000):
        self.path = Path(path) if path else None
        self.max_size = max_size
        self._ids: "OrderedDict[str, None]" = OrderedDict()
        self._load()

    def _load(self) -> None:
        if not self.path or not self.path.is_file():
            return
        try:
            for tid in json.loads(self.path.read_text(encoding="utf-8")):
                self._ids[str(tid)] = None
        except (ValueError, OSError) as exc:
            log.warning("상태 파일을 읽지 못해 새로 시작합니다 (%s): %s", self.path, exc)

    def __contains__(self, threat_id: str) -> bool:
        return str(threat_id) in self._ids

    def __len__(self) -> int:
        return len(self._ids)

    def add(self, threat_id: str) -> None:
        self._ids[str(threat_id)] = None
        self._ids.move_to_end(str(threat_id))
        while len(self._ids) > self.max_size:
            self._ids.popitem(last=False)
        self._save()

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(list(self._ids)), encoding="utf-8")
        os.replace(tmp, self.path)
