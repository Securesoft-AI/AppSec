"""Entorno de Alembic. La conexión la pasa Database.migrate (no hay alembic.ini)."""

from alembic import context
from alembic.operations import ops
from sqlalchemy.schema import DefaultClause

from appsec_ai.service.db import Base, _server_default


def _defaults_for_new_columns(_context, _revision, directives):
    """Al generar una migración, una columna obligatoria nueva recibe un valor para las filas que ya existen."""
    def walk(items):
        for op in items:
            if isinstance(op, ops.AddColumnOp) and not op.column.nullable and op.column.server_default is None:
                model = Base.metadata.tables[op.table_name].c[op.column.name]
                op.column.server_default = DefaultClause(_server_default(model))
            walk(getattr(op, "ops", []))
    for script in directives:
        walk(script.upgrade_ops.ops)


connection = context.config.attributes["connection"]
context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True,
                  process_revision_directives=_defaults_for_new_columns,
                  render_as_batch=connection.dialect.name == "sqlite")  # SQLite no altera columnas
with context.begin_transaction():
    context.run_migrations()
