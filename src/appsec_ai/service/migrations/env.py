"""Entorno de Alembic. La conexión la pasa Database.migrate (no hay alembic.ini)."""

from alembic import context

from appsec_ai.service.db import Base

connection = context.config.attributes["connection"]
context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True,
                  render_as_batch=connection.dialect.name == "sqlite")  # SQLite no altera columnas
with context.begin_transaction():
    context.run_migrations()
