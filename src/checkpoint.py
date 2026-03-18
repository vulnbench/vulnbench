"""Checkpoint manager for pipeline state persistence."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import CVERecord, PipelineState

logger = logging.getLogger(__name__)

DEFAULT_CHECKPOINT_DIR = Path("data/checkpoints")
STATE_FILE = "pipeline_state.json"
RECORDS_FILE = "records.json"


class CheckpointManager:
    """Save and restore pipeline state for resume support."""

    def __init__(self, checkpoint_dir: Optional[Path] = None):
        self.checkpoint_dir = checkpoint_dir or DEFAULT_CHECKPOINT_DIR
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    @property
    def state_path(self) -> Path:
        return self.checkpoint_dir / STATE_FILE

    @property
    def records_path(self) -> Path:
        return self.checkpoint_dir / RECORDS_FILE

    def has_checkpoint(self) -> bool:
        return self.state_path.exists()

    def load_state(self) -> PipelineState:
        """Load pipeline state from checkpoint."""
        if not self.state_path.exists():
            return PipelineState()
        try:
            data = json.loads(self.state_path.read_text())
            return PipelineState(**data)
        except Exception as e:
            logger.warning("Failed to load checkpoint state: %s", e)
            return PipelineState()

    def save_state(self, state: PipelineState) -> None:
        """Save pipeline state atomically."""
        state.last_updated = datetime.utcnow().isoformat()
        self._atomic_write(self.state_path, state.model_dump_json(indent=2))

    def load_records(self) -> list[CVERecord]:
        """Load saved CVE records from checkpoint."""
        if not self.records_path.exists():
            return []
        try:
            data = json.loads(self.records_path.read_text())
            return [CVERecord(**r) for r in data]
        except Exception as e:
            logger.warning("Failed to load checkpoint records: %s", e)
            return []

    def save_records(self, records: list[CVERecord]) -> None:
        """Save CVE records atomically."""
        data = json.dumps([r.model_dump() for r in records], indent=2)
        self._atomic_write(self.records_path, data)

    def save(self, state: PipelineState, records: list[CVERecord]) -> None:
        """Save both state and records."""
        self.save_state(state)
        self.save_records(records)
        logger.info(
            "Checkpoint saved: stage=%s, records=%d",
            state.stage,
            len(records),
        )

    def clear(self) -> None:
        """Remove checkpoint files."""
        for path in (self.state_path, self.records_path):
            if path.exists():
                path.unlink()
        logger.info("Checkpoint cleared")

    def _atomic_write(self, path: Path, content: str) -> None:
        """Write to a temp file then rename for crash safety."""
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content)
        tmp.rename(path)
