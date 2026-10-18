"""Bitbucket por organizacion

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('bitbucket_config', sa.JSON(), server_default='{}', nullable=False))


def downgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.drop_column('bitbucket_config')

