"""Update the school model to accomodate regestration for students

Revision ID: 8031d5c92fb2
Revises: 47626039e23c
Create Date: 2025-01-30 00:32:05.822528

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8031d5c92fb2'
down_revision = '47626039e23c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('schools', schema=None) as batch_op:
        batch_op.add_column(sa.Column('registration_fee_total', sa.Float(), nullable=True))
        batch_op.alter_column('membership_no',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('schools', schema=None) as batch_op:
        batch_op.alter_column('membership_no',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.drop_column('registration_fee_total')

    # ### end Alembic commands ###
