"""Initial migration

Revision ID: f4bb525691a7
Revises: 
Create Date: 2024-10-19 01:08:08.271267

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f4bb525691a7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    # Add the column (initially nullable to prevent errors)
    op.add_column('users', sa.Column('roles', sa.String(length=20), nullable=True))

    # Manually set the value for existing rows
    op.execute("UPDATE users SET roles = 'user' WHERE roles IS NULL")

    # Then set the column as not nullable
    op.alter_column('users', 'roles', nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.VARCHAR(length=20), autoincrement=False, nullable=False))
        batch_op.drop_column('roles')

    # ### end Alembic commands ###