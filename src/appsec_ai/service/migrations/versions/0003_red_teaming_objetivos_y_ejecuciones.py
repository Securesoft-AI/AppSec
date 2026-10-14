"""Red teaming: objetivos y ejecuciones

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('redteam_targets',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('installation_id', sa.BigInteger(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('url', sa.String(length=1000), nullable=False),
    sa.Column('host', sa.String(length=300), nullable=False),
    sa.Column('method', sa.String(length=10), nullable=False),
    sa.Column('body_template', sa.Text(), nullable=False),
    sa.Column('response_path', sa.String(length=200), nullable=False),
    sa.Column('headers', sa.JSON(), nullable=False),
    sa.Column('verified_method', sa.String(length=10), nullable=False),
    sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.String(length=200), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['installation_id'], ['installations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('redteam_targets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_redteam_targets_host'), ['host'], unique=False)
        batch_op.create_index(batch_op.f('ix_redteam_targets_installation_id'), ['installation_id'], unique=False)

    op.create_table('redteam_runs',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('target_id', sa.Integer(), nullable=False),
    sa.Column('installation_id', sa.BigInteger(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('requested_by', sa.String(length=200), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('summary', sa.JSON(), nullable=False),
    sa.Column('result', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['installation_id'], ['installations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_id'], ['redteam_targets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('redteam_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_redteam_runs_installation_id'), ['installation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_redteam_runs_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_redteam_runs_target_id'), ['target_id'], unique=False)


def downgrade():
    with op.batch_alter_table('redteam_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_redteam_runs_target_id'))
        batch_op.drop_index(batch_op.f('ix_redteam_runs_status'))
        batch_op.drop_index(batch_op.f('ix_redteam_runs_installation_id'))

    op.drop_table('redteam_runs')
    with op.batch_alter_table('redteam_targets', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_redteam_targets_installation_id'))
        batch_op.drop_index(batch_op.f('ix_redteam_targets_host'))

    op.drop_table('redteam_targets')
