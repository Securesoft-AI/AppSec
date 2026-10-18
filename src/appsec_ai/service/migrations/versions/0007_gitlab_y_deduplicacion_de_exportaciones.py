"""GitLab y deduplicacion de exportaciones

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('integration_exports',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('installation_id', sa.BigInteger(), nullable=False),
    sa.Column('provider', sa.String(length=20), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('external_key', sa.String(length=100), nullable=False),
    sa.Column('url', sa.String(length=500), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['installation_id'], ['installations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('installation_id', 'provider', 'fingerprint', name='uq_export')
    )
    with op.batch_alter_table('integration_exports', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_integration_exports_installation_id'), ['installation_id'], unique=False)

    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('gitlab_config', sa.JSON(), server_default='{}', nullable=False))


def downgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.drop_column('gitlab_config')

    with op.batch_alter_table('integration_exports', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_integration_exports_installation_id'))

    op.drop_table('integration_exports')
