"""Migraciones: el esquema migrado coincide con los modelos y las bases de datos antiguas se adoptan."""

import os
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from appsec_ai.service import db as db_module
from appsec_ai.service.db import Base, Database, Installation, Scan


def _head() -> str:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(db_module.__file__).with_name("migrations")))
    return ScriptDirectory.from_config(cfg).get_current_head()


def _diff(db: Database) -> list:
    with db.engine.connect() as conn:
        return compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)


def _version(db: Database) -> str:
    with db.engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


@pytest.fixture(params=["sqlite", "postgres"])
def url(request, tmp_path):
    if request.param == "sqlite":
        return f"sqlite:///{tmp_path}/db.sqlite"
    pg = os.environ.get("TEST_POSTGRES_URL")  # p. ej. postgresql+psycopg://localhost/appsec_test
    if not pg:
        pytest.skip("TEST_POSTGRES_URL no definida")
    engine = create_engine(pg)
    with engine.begin() as conn:  # base de datos vacía para cada test
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    engine.dispose()
    return pg


def test_new_database_matches_models(url):
    db = Database(url)
    db.migrate()
    assert _version(db) == _head()
    # Si falla: se ha cambiado un modelo sin crear la migración correspondiente
    # (alembic revision --autogenerate, ver docs/DESPLIEGUE.md).
    assert _diff(db) == []
    db.migrate()  # idempotente
    assert _version(db) == _head()


def test_legacy_database_is_adopted(url):
    """Una base de datos creada con create_all antes de que existieran algunas columnas y tablas."""
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE installations (id BIGINT PRIMARY KEY, account_login VARCHAR(200) NOT NULL,"
                          " account_type VARCHAR(20) NOT NULL, plan VARCHAR(20) NOT NULL, active BOOLEAN NOT NULL,"
                          " created_at TIMESTAMP WITH TIME ZONE NOT NULL)"))
        conn.execute(text("INSERT INTO installations VALUES (7, 'acme', 'Organization', 'free', true,"
                          " CURRENT_TIMESTAMP)"))
        conn.execute(text("CREATE TABLE repositories (id BIGINT PRIMARY KEY, installation_id BIGINT NOT NULL"
                          " REFERENCES installations(id) ON DELETE CASCADE, full_name VARCHAR(300) NOT NULL,"
                          " default_branch VARCHAR(200) NOT NULL, private BOOLEAN NOT NULL, active BOOLEAN NOT NULL)"))
        conn.execute(text("INSERT INTO repositories VALUES (70, 7, 'acme/api', 'main', true, true)"))
    engine.dispose()

    db = Database(url)
    db.migrate()
    assert _version(db) == _head()
    with db.session() as s:
        inst = s.get(Installation, 7)
        assert inst.modules == [] and inst.language == "" and inst.ai_requests_used == 0
        assert inst.eval_opt_in is False and inst.trial_ends_at is None
        assert inst.repositories[0].services is None
        s.add(Scan(repository_id=70, kind="full", head_sha="abc"))  # tablas nuevas creadas
        s.commit()
    tables = set(inspect(db.engine).get_table_names())
    assert {"scans", "pentest_requests", "finding_feedback", "fix_requests", "waitlist"} <= tables
    db.migrate()
    assert _version(db) == _head()


def test_upgrade_keeps_existing_rows(url):
    """Cada migración se aplica sobre datos reales: aquí, 0002 sobre un pentest creado con el esquema 0001."""
    from alembic import command

    from appsec_ai.service.db import PentestRequest, _alembic_config

    db = Database(url)
    cfg = _alembic_config()
    with db.engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0001")
        conn.execute(text("INSERT INTO installations (id, account_login, account_type, plan, active, eval_opt_in,"
                          " language, stripe_customer_id, stripe_subscription_id, modules, subscription_status,"
                          " usage_period, ai_requests_used, billing_event_at, created_at) VALUES (7, 'acme',"
                          " 'Organization', 'free', true, false, '', '', '', '[]', '', '', 0, 0, CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO pentest_requests (installation_id, requested_by, kind, target, scope,"
                          " preferred_dates, contact_email, status, report, created_at, updated_at) VALUES (7, 'ana',"
                          " 'web', 'https://acme.com', '', '', 'a@acme.com', 'requested', '{}', CURRENT_TIMESTAMP,"
                          " CURRENT_TIMESTAMP)"))
    db.migrate()
    with db.session() as s:
        row = s.query(PentestRequest).one()
        assert row.notes == "" and row.accepted_at is None
    assert _diff(db) == []
