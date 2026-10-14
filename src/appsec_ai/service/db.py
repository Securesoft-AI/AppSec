"""Modelo de datos del SaaS (SQLAlchemy). Postgres en producción, SQLite en desarrollo y tests."""

from __future__ import annotations

import datetime as dt
import re
import unicodedata
from enum import Enum
from pathlib import Path

from sqlalchemy import (JSON, BigInteger, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
                        create_engine, inspect, select, text, update)
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
    # El cliente acepta por escrito que su feedback (con fragmentos de código) mejore el triage.
    eval_opt_in: Mapped[bool] = mapped_column(default=False)
    # Idioma de lo que se publica en GitHub y del triage ("es" | "en"); vacío = REPORT_LANGUAGE.
    language: Mapped[str] = mapped_column(String(5), default="")
    # Facturación (Stripe) y uso. El plan efectivo lo calcula plans.effective_plan.
    trial_ends_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stripe_customer_id: Mapped[str] = mapped_column(String(100), default="", index=True)
    stripe_subscription_id: Mapped[str] = mapped_column(String(100), default="")
    # Servicios y paquetes contratados (claves de appsec_ai.services), según la suscripción de Stripe.
    modules: Mapped[list] = mapped_column(JSON, default=list)
    subscription_status: Mapped[str] = mapped_column(String(30), default="")
    usage_period: Mapped[str] = mapped_column(String(7), default="")  # AAAA-MM
    ai_requests_used: Mapped[int] = mapped_column(Integer, default=0)
    billing_event_at: Mapped[int] = mapped_column(BigInteger, default=0)  # último evento de Stripe aplicado
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
    # Servicios que el usuario quiere en este repositorio; None = todos los contratados.
    services: Mapped[list | None] = mapped_column(JSON, nullable=True)

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
    MANUAL = "manual"  # "Escanear ahora" desde el panel: rama por defecto, servicios elegidos


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
    # Servicios pedidos para este escaneo (escaneo bajo demanda); None = los del repositorio.
    services: Mapped[list | None] = mapped_column(JSON, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(200), default="")
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


class PentestStatus(str, Enum):
    REQUESTED = "requested"      # el cliente lo ha pedido
    SCOPING = "scoping"          # el equipo concreta alcance, fechas y presupuesto
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    REPORTED = "reported"        # informe entregado
    CANCELLED = "cancelled"


class PentestRequest(Base):
    """Pentest manual pedido desde el panel. Lo gestiona el equipo de seguridad desde la vista Equipo.

    Ciclo: el cliente lo solicita, el equipo concreta alcance y presupuesto, el cliente acepta el presupuesto,
    el equipo lo programa, lo ejecuta y publica el informe. El cliente puede cancelarlo antes de aceptar.
    """

    __tablename__ = "pentest_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int] = mapped_column(ForeignKey("installations.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(20))                 # web | api | mobile | llm | network
    target: Mapped[str] = mapped_column(String(500))
    scope: Mapped[str] = mapped_column(Text, default="")
    preferred_dates: Mapped[str] = mapped_column(String(200), default="")
    contact_email: Mapped[str] = mapped_column(String(320))
    status: Mapped[str] = mapped_column(String(20), default=PentestStatus.REQUESTED.value, index=True)
    quote_eur: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")            # mensaje del equipo al cliente
    accepted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    report: Mapped[dict] = mapped_column(JSON, default=dict)       # resumen y hallazgos (cifrado si hay clave)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingFeedback(Base):
    """Un usuario marca un hallazgo como útil o no útil (RF-3.8). Uno por usuario y hallazgo."""

    __tablename__ = "finding_feedback"
    __table_args__ = (UniqueConstraint("repository_id", "fingerprint", "user_login", name="uq_feedback"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int] = mapped_column(ForeignKey("installations.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(200))
    user_login: Mapped[str] = mapped_column(String(200))
    useful: Mapped[bool] = mapped_column()
    comment: Mapped[str] = mapped_column(Text, default="")
    finding: Mapped[dict] = mapped_column(JSON, default=dict)  # copia del hallazgo (cifrada si hay clave)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RedTeamTarget(Base):
    """Endpoint con LLM del cliente contra el que se puede lanzar red teaming (RF-2.7).

    No se ejecuta nada hasta que `verified_method` demuestra que el dominio es del cliente. Las cabeceras
    pueden llevar claves de API, así que se guardan cifradas.
    """

    __tablename__ = "redteam_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int] = mapped_column(ForeignKey("installations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    url: Mapped[str] = mapped_column(String(1000))
    host: Mapped[str] = mapped_column(String(300), index=True)
    method: Mapped[str] = mapped_column(String(10), default="POST")
    body_template: Mapped[str] = mapped_column(Text, default='{"input": "{prompt}"}')
    response_path: Mapped[str] = mapped_column(String(200), default="")
    headers: Mapped[dict] = mapped_column(JSON, default=dict)      # cifrado si hay clave (puede llevar tokens)
    verified_method: Mapped[str] = mapped_column(String(10), default="")  # "" | "http" | "dns"
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RedTeamRun(Base):
    """Una ejecución de red teaming sobre un objetivo. Hace también de cola de trabajos (status = queued)."""

    __tablename__ = "redteam_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("redteam_targets.id", ondelete="CASCADE"), index=True)
    installation_id: Mapped[int] = mapped_column(ForeignKey("installations.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.QUEUED.value, index=True)
    requested_by: Mapped[str] = mapped_column(String(200), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)      # recuento, no lleva código: sin cifrar
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # sondas y evidencias (cifrado si hay clave)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Registro de auditoría append-only (RF-4.8): acciones sensibles sobre una instalación.

    No se modifica ni se borra desde la aplicación (solo el borrado en cascada al eliminar la instalación).
    El detalle no guarda secretos ni código: solo identificadores y cambios de estado.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int | None] = mapped_column(
        ForeignKey("installations.id", ondelete="CASCADE"), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(200))          # login del usuario, "admin", "stripe", "system"
    action: Mapped[str] = mapped_column(String(50), index=True)  # p. ej. "scan.requested", "pentest.updated"
    target: Mapped[str] = mapped_column(String(300), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class WaitlistEntry(Base):
    """Interesados que dejan su email en la landing."""

    __tablename__ = "waitlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    company: Mapped[str] = mapped_column(String(200), default="")
    lang: Mapped[str] = mapped_column(String(5), default="es")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


MIGRATION_LOCK = 0x61707073  # clave del bloqueo de Postgres durante las migraciones


class Database:
    def __init__(self, url: str, cipher=None):
        self.cipher = cipher  # crypto.Cipher: cifra resultados y detalles con código del cliente
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {"pool_pre_ping": True}
        self.engine = create_engine(url, **kwargs)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)

    def migrate(self):
        """Lleva el esquema a la última migración. Lo llaman la API y el worker al arrancar.

        Una base de datos creada antes de las migraciones (con create_all) se adopta: se añaden las tablas
        y columnas que le falten y se marca como al día. En Postgres un bloqueo evita que la API y los
        workers migren a la vez.
        """
        from alembic import command

        cfg = _alembic_config()
        with self.engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": MIGRATION_LOCK})
            cfg.attributes["connection"] = conn
            tables = set(inspect(conn).get_table_names())
            if "alembic_version" not in tables and "installations" in tables:
                _adopt_legacy(conn)
                command.stamp(cfg, "head")
            else:
                command.upgrade(cfg, "head")

    def session(self) -> Session:
        return self.session_factory()

    def claim_next_scan(self) -> Scan | None:
        """Toma el siguiente escaneo en cola de forma atómica (varios workers en paralelo)."""
        return self._claim(Scan, started_at=utcnow())

    def claim_next_fix(self) -> FixRequest | None:
        return self._claim(FixRequest)

    def claim_next_redteam(self) -> "RedTeamRun | None":
        return self._claim(RedTeamRun)

    def audit(self, installation_id, actor: str, action: str, target: str = "", detail: dict | None = None,
              ip: str = "", session: Session | None = None):
        """Añade una entrada al registro de auditoría.

        Si se pasa `session` (una transacción ya abierta), la entrada se escribe en ella y es atómica con la
        acción. Si no, se abre una transacción propia. En SQLite hay que reusar la sesión abierta porque el
        fichero se bloquea para escrituras.
        """
        entry = AuditLog(installation_id=installation_id, actor=actor, action=action, target=target[:300],
                         detail=detail or {}, ip=ip[:64])
        if session is not None:
            session.add(entry)
        else:
            with self.session() as s, s.begin():
                s.add(entry)

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

    def new_migration(self, message: str) -> str:
        """Genera la migración de los cambios en los modelos (la base de datos debe estar al día)."""
        from alembic import command
        from alembic.script import ScriptDirectory

        self.migrate()
        cfg = _alembic_config()
        head = ScriptDirectory.from_config(cfg).get_current_head()
        with self.engine.begin() as conn:
            cfg.attributes["connection"] = conn
            rev = f"{int(head) + 1:04d}"
            script = command.revision(cfg, message=message, autogenerate=True, rev_id=rev)
        # Nombre de fichero en ASCII y sin los comentarios que añade Alembic.
        src = Path(script.path)
        slug = re.sub(r"[^a-z0-9]+", "_", unicodedata.normalize("NFKD", message).encode("ascii", "ignore")
                      .decode().lower()).strip("_")[:40]
        dest = src.with_name(f"{rev}_{slug}.py")
        dest.write_text("".join(line for line in src.read_text(encoding="utf-8").splitlines(keepends=True)
                                if "### commands auto generated" not in line and "### end Alembic" not in line),
                        encoding="utf-8")
        if dest != src:
            src.unlink()
        return str(dest)


def _alembic_config():
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).with_name("migrations")))
    return cfg


def _adopt_legacy(conn):
    """Completa una base de datos creada con create_all antes de las migraciones."""
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    op = Operations(MigrationContext.configure(conn))
    insp = inspect(conn)
    existing = set(insp.get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            table.create(conn)
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in have:
                op.add_column(table.name, Column(col.name, col.type, nullable=col.nullable,
                                                 server_default=None if col.nullable else _server_default(col)))
        indexes = {i["name"] for i in insp.get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in indexes:
                index.create(conn)


def _server_default(col):
    """Valor para las filas que ya existen al añadir una columna obligatoria."""
    default = col.default.arg if col.default is not None else None
    if col.default is not None and col.default.is_callable:
        default = default(None)  # utcnow, list, dict
    if isinstance(default, dt.datetime):
        return text("CURRENT_TIMESTAMP")
    if isinstance(default, (list, dict)):
        return "[]" if isinstance(default, list) else "{}"
    if isinstance(default, bool):
        return text("true" if default else "false")
    if isinstance(default, (int, str)):
        return str(default)
    raise RuntimeError(f"columna {col.table.name}.{col.name} sin valor por defecto para filas existentes")
