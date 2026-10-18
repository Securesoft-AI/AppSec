"""SSO OIDC por organizacion

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('oidc_config', sa.JSON(), server_default='{}', nullable=False))


def downgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.drop_column('oidc_config')

