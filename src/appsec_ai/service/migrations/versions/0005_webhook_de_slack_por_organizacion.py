"""Webhook de Slack por organización

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('slack_webhook', sa.JSON(), server_default='{}', nullable=False))


def downgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.drop_column('slack_webhook')

