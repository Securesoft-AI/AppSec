"""Configuración de Jira por organización

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('jira_config', sa.JSON(), server_default='{}', nullable=False))


def downgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.drop_column('jira_config')

