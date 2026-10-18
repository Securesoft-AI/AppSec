"""GitLab como plataforma de código

Revision ID: 0010
Revises: 0009
"""

import sqlalchemy as sa
from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('gitlab_scm', sa.JSON(), server_default='{}', nullable=False))

    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.add_column(sa.Column('provider', sa.String(length=20), server_default='github', nullable=False))



def downgrade():
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.drop_column('provider')

    with op.batch_alter_table('installations', schema=None) as batch_op:
        batch_op.drop_column('gitlab_scm')

