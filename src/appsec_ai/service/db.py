"""Modelo de datos del SaaS (SQLAlchemy). Postgres en producción, SQLite en desarrollo y tests."""

from __future__ import annotations

import datetime as dt
from enum import Enum

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class Installation(Base):
    """Una instalación de la GitHub App = una organización o cuenta cliente."""

    __tablename__ = "installations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)  # id de instalación de GitHub
    account_login: Mapped[str] = mapped_column(String(200))
    account_type: Mapped[str] = mapped_column(String(20), default="Organization")
    plan: Mapped[str] = mapped_column(String(20), default="free")
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    repositories: Mapped[list["Repository"]] = relationship(back_populates="installation", cascade="all, delete-orphan")


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)  # id de repositorio de GitHub
    installation_id: Mapped[int] = mapped_column(ForeignKey("installations.id", ondelete="CASCADE"), index=True)
    full_name: Mapped[str] = mapped_column(String(300), index=True)
    default_branch: Mapped[str] = mapped_column(String(200), default="main")
    private: Mapped[bool] = mapped_column(default=True)
    active: Mapped[bool] = mapped_column(default=True)

    installation: Mapped[Installation] = relationship(back_populates="repositories")
    scans: Mapped[list["Scan"]] = relationship(back_populates="repository", cascade="all, delete-orphan")


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanKind(str, Enum):
    PULL_REQUEST = "pull_request"
    FULL = "full"


class Scan(Base):
    """Escaneo de un commit. Hace también de cola de trabajos (status = queued)."""

    __tablename__ = "scans"
    __table_args__ = (UniqueConstraint("repository_id", "head_sha", "kind", name="uq_scan_commit"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.QUEUED.value, index=True)
    head_sha: Mapped[str] = mapped_column(String(64))
    ref: Mapped[str] = mapped_column(String(300), default="")
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    check_run_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)      # recuento por severidad, uso de IA...
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # ScanResult serializado
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    repository: Mapped[Repository] = relationship(back_populates="scans")


class FixRequest(Base):
    """Petición de "Abrir PR con la corrección" sobre un escaneo. También es cola de trabajos."""

    __tablename__ = "fix_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True, unique=True)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.QUEUED.value, index=True)
    requested_by: Mapped[str] = mapped_column(String(200), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    pr_url: Mapped[str] = mapped_column(String(500), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # ficheros corregidos y descartados
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Database:
    def __init__(self, url: str, cipher=None):
        self.cipher = cipher  # crypto.Cipher: cifra resultados y detalles con código del cliente
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {"pool_pre_ping": True}
        self.engine = create_engine(url, **kwargs)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)

    def create_all(self):
        Base.metadata.create_all(self.engine)

    def session(self) -> Session:
        return self.session_factory()

    def claim_next_scan(self) -> Scan | None:
        """Toma el siguiente escaneo en cola de forma atómica (varios workers en paralelo)."""
        return self._claim(Scan, started_at=utcnow())

    def claim_next_fix(self) -> FixRequest | None:
        return self._claim(FixRequest)

    def _claim(self, model, **values):
        for _ in range(5):
            with self.session() as s, s.begin():
                job_id = s.scalars(
                    select(model.id).where(model.status == ScanStatus.QUEUED.value).order_by(model.id).limit(1)
                ).first()
                if job_id is None:
                    return None
                # UPDATE condicional: si otro worker lo tomó antes, no se modifica ninguna fila.
                claimed = s.execute(
                    update(model)
                    .where(model.id == job_id, model.status == ScanStatus.QUEUED.value)
                    .values(status=ScanStatus.RUNNING.value, attempts=model.attempts + 1, **values)
                ).rowcount
            if claimed:
                with self.session() as s:
                    return s.get(model, job_id)
        return None
