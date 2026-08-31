#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Forensic evidence collection and chain of custody."""

import hashlib
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("LUMENOS_SANDBOX")


@dataclass
class EvidenceItem:
    """A single piece of forensic evidence."""
    evidence_id: str
    bunker_id: str
    description: str
    source: str  # e.g. "vm_checkpoint", "event_log", "memory_dump"
    sha256: str
    collected_at: str = ""
    collector: str = "lumenos_sandbox"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.collected_at:
            self.collected_at = datetime.now().isoformat()


@dataclass
class EvidenceChain:
    """Ordered chain of custody for a bunker analysis session."""
    bunker_id: str
    items: List[EvidenceItem] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def add(self, item: EvidenceItem) -> None:
        self.items.append(item)
        logger.info("Evidence added: %s (%s)", item.evidence_id, item.source)

    def verify(self) -> bool:
        """Verify all item hashes match their SHA-256."""
        for item in self.items:
            # Re-hash the evidence_id + description as a minimal integrity check
            payload = f"{item.evidence_id}:{item.description}:{item.source}".encode()
            expected = hashlib.sha256(payload).hexdigest()
            if expected != item.sha256:
                logger.error("Evidence tampered: %s", item.evidence_id)
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bunker_id": self.bunker_id,
            "created_at": self.created_at,
            "item_count": len(self.items),
            "chain_valid": self.verify(),
            "items": [asdict(i) for i in self.items],
        }


def _hash_file(path: Path) -> str:
    """SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_evidence(bunker_id: str, evidence_dir: str = "evidence") -> EvidenceChain:
    """Collect forensic evidence from disk artifacts for a bunker.

    Gathers:
      - State DB snapshot
      - Decontamination reports from logs/
      - Any checkpoint metadata from snapshots/
    """
    chain = EvidenceChain(bunker_id=bunker_id)
    out_dir = Path(evidence_dir) / bunker_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. State DB
    db_path = Path("lumenos_state.db")
    if db_path.exists():
        item = EvidenceItem(
            evidence_id=f"{bunker_id}_statedb",
            bunker_id=bunker_id,
            description="SQLite state database snapshot",
            source="state_db",
            sha256=_hash_file(db_path),
            metadata={"path": str(db_path), "size": db_path.stat().st_size},
        )
        chain.add(item)

    # 2. Decontamination reports
    logs_dir = Path("logs")
    if logs_dir.is_dir():
        for report_path in logs_dir.glob(f"{bunker_id}_decontamination_*.json"):
            item = EvidenceItem(
                evidence_id=f"{bunker_id}_decon_{report_path.stem}",
                bunker_id=bunker_id,
                description=f"Decontamination report: {report_path.name}",
                source="decontamination_report",
                sha256=_hash_file(report_path),
                metadata={"path": str(report_path)},
            )
            chain.add(item)

    # 3. Snapshot files
    snaps_dir = Path("snapshots")
    if snaps_dir.is_dir():
        for snap in snaps_dir.glob(f"{bunker_id}*"):
            if snap.is_file():
                item = EvidenceItem(
                    evidence_id=f"{bunker_id}_snap_{snap.name}",
                    bunker_id=bunker_id,
                    description=f"Snapshot file: {snap.name}",
                    source="snapshot",
                    sha256=_hash_file(snap),
                    metadata={"path": str(snap), "size": snap.stat().st_size},
                )
                chain.add(item)

    logger.info("Evidence collected: %d items for %s", len(chain.items), bunker_id)
    return chain


def export_evidence(chain: EvidenceChain, output_path: str) -> str:
    """Export evidence chain as JSON. Returns the output path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(chain.to_dict(), f, indent=2, default=str)
    logger.info("Evidence exported: %s (%d items)", output_path, len(chain.items))
    return output_path
