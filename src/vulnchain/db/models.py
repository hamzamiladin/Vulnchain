"""SQLAlchemy ORM models for the RedTeam Agent database."""

import uuid
from typing import Any

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, Float,
    ForeignKey, Index, Integer, String, Text, func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Any = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_url: Any = Column(Text, nullable=False)
    repo_name: Any = Column(Text, nullable=False)
    pr_number: Any = Column(Integer, nullable=True)
    commit_sha: Any = Column(Text, nullable=True)
    status: Any = Column(String(20), nullable=False, default="pending", server_default="pending")
    started_at: Any = Column(DateTime(timezone=True), nullable=True)
    completed_at: Any = Column(DateTime(timezone=True), nullable=True)
    created_at: Any = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    error_message: Any = Column(Text, nullable=True)

    findings: Any = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    attack_chains: Any = relationship("AttackChain", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("status IN ('pending','running','done','failed')", name="ck_scans_status"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_repo_url", "repo_url"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Any = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Any = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    source: Any = Column(String(20), nullable=False)
    rule_id: Any = Column(Text, nullable=False)
    severity: Any = Column(String(10), nullable=False)
    file_path: Any = Column(Text, nullable=False)
    line_start: Any = Column(Integer, nullable=True)
    line_end: Any = Column(Integer, nullable=True)
    message: Any = Column(Text, nullable=False)
    fix_suggestion: Any = Column(Text, nullable=True)
    is_ai_generated: Any = Column(Boolean, nullable=False, default=False)
    ai_confidence: Any = Column(Float, nullable=True)
    raw_json: Any = Column(JSONB, nullable=True)
    created_at: Any = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    scan: Any = relationship("Scan", back_populates="findings")

    __table_args__ = (
        CheckConstraint("source IN ('semgrep','joern','ai_detector','llm_review','dependency','progpilot','pysa')", name="ck_findings_source"),
        CheckConstraint("severity IN ('critical','high','medium','low','info')", name="ck_findings_severity"),
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_severity", "severity"),
    )


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Any = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Any = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    title: Any = Column(Text, nullable=False)
    combined_severity: Any = Column(String(10), nullable=False)
    steps: Any = Column(JSONB, nullable=False)
    finding_ids: Any = Column(JSONB, nullable=False, server_default="'[]'")
    business_impact: Any = Column(Text, nullable=False)
    cvss_score: Any = Column(Float, nullable=True)
    created_at: Any = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    scan: Any = relationship("Scan", back_populates="attack_chains")

    __table_args__ = (
        CheckConstraint("combined_severity IN ('critical','high','medium')", name="ck_chains_severity"),
        Index("idx_attack_chains_scan_id", "scan_id"),
    )
