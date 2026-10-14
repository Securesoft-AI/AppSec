"""Esquema inicial (el de los modelos al introducir las migraciones).

Revision ID: 0001
Revises: 
"""

import sqlalchemy as sa
from alembic import op

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('installations',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('account_login', sa.String(length=200), nullable=False),
    sa.Column('account_type', sa.String(length=20), nullable=False),
    sa.Column('plan', sa.String(length=20), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('eval_opt_in', sa.Boolean(), nullable=False),
    sa.Column('language', sa.String(length=5), nullable=False),
    sa.Column('trial_ends_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('stripe_customer_id', sa.String(length=100), nullable=False),
    sa.Column('stripe_subscription_id', sa.String(length=100), nullable=False),
    sa.Column('modules', sa.JSON(), nullable=False),
    sa.Column('subscription_status', sa.String(length=30), nullable=False),
    sa.Column('usage_period', sa.String(length=7), nullable=False),
    sa.Column('ai_requests_used', sa.Integer(), nullable=False),
    sa.Column('billing_event_at', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_installations_stripe_customer_id'), ['stripe_customer_id'], unique=False)

    op.create_table('waitlist',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('company', sa.String(length=200), nullable=False),
    sa.Column('lang', sa.String(length=5), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('waitlist', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_waitlist_email'), ['email'], unique=True)

    op.create_table('pentest_requests',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('installation_id', sa.BigInteger(), nullable=False),
    sa.Column('requested_by', sa.String(length=200), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('target', sa.String(length=500), nullable=False),
    sa.Column('scope', sa.Text(), nullable=False),
    sa.Column('preferred_dates', sa.String(length=200), nullable=False),
    sa.Column('contact_email', sa.String(length=320), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('quote_eur', sa.Integer(), nullable=True),
    sa.Column('report', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['installation_id'], ['installations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('pentest_requests', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pentest_requests_installation_id'), ['installation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pentest_requests_status'), ['status'], unique=False)

    op.create_table('repositories',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('installation_id', sa.BigInteger(), nullable=False),
    sa.Column('full_name', sa.String(length=300), nullable=False),
    sa.Column('default_branch', sa.String(length=200), nullable=False),
    sa.Column('private', sa.Boolean(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('services', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['installation_id'], ['installations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_repositories_full_name'), ['full_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_repositories_installation_id'), ['installation_id'], unique=False)

    op.create_table('scans',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('repository_id', sa.BigInteger(), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('head_sha', sa.String(length=64), nullable=False),
    sa.Column('ref', sa.String(length=300), nullable=False),
    sa.Column('pr_number', sa.Integer(), nullable=True),
    sa.Column('services', sa.JSON(), nullable=True),
    sa.Column('requested_by', sa.String(length=200), nullable=False),
    sa.Column('check_run_id', sa.BigInteger(), nullable=True),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('summary', sa.JSON(), nullable=False),
    sa.Column('result', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('repository_id', 'head_sha', 'kind', name='uq_scan_commit')
    )
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scans_repository_id'), ['repository_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_status'), ['status'], unique=False)

    op.create_table('finding_feedback',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('installation_id', sa.BigInteger(), nullable=False),
    sa.Column('repository_id', sa.BigInteger(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('rule_id', sa.String(length=200), nullable=False),
    sa.Column('user_login', sa.String(length=200), nullable=False),
    sa.Column('useful', sa.Boolean(), nullable=False),
    sa.Column('comment', sa.Text(), nullable=False),
    sa.Column('finding', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['installation_id'], ['installations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('repository_id', 'fingerprint', 'user_login', name='uq_feedback')
    )
    with op.batch_alter_table('finding_feedback', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_finding_feedback_installation_id'), ['installation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_finding_feedback_repository_id'), ['repository_id'], unique=False)

    op.create_table('fix_requests',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('requested_by', sa.String(length=200), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('pr_url', sa.String(length=500), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('fix_requests', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_fix_requests_scan_id'), ['scan_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_fix_requests_status'), ['status'], unique=False)



def downgrade():
    with op.batch_alter_table('fix_requests', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_fix_requests_status'))
        batch_op.drop_index(batch_op.f('ix_fix_requests_scan_id'))

    op.drop_table('fix_requests')
    with op.batch_alter_table('finding_feedback', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_finding_feedback_repository_id'))
        batch_op.drop_index(batch_op.f('ix_finding_feedback_installation_id'))

    op.drop_table('finding_feedback')
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scans_status'))
        batch_op.drop_index(batch_op.f('ix_scans_repository_id'))

    op.drop_table('scans')
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_repositories_installation_id'))
        batch_op.drop_index(batch_op.f('ix_repositories_full_name'))

    op.drop_table('repositories')
    with op.batch_alter_table('pentest_requests', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_pentest_requests_status'))
        batch_op.drop_index(batch_op.f('ix_pentest_requests_installation_id'))

    op.drop_table('pentest_requests')
    with op.batch_alter_table('waitlist', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_waitlist_email'))

    op.drop_table('waitlist')
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_installations_stripe_customer_id'))

    op.drop_table('installations')
