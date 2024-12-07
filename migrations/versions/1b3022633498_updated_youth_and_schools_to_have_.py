"""updated youth and schools to have regestration paymyment status

Revision ID: 1b3022633498
Revises: 5b669be48c90
Create Date: 2024-12-06 13:01:09.765469

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1b3022633498'
down_revision = '5b669be48c90'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('schools', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reg_payment_status', sa.String(length=20), nullable=True))

    with op.batch_alter_table('youths', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reg_payment_status', sa.String(length=20), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('youths', schema=None) as batch_op:
        batch_op.drop_column('reg_payment_status')

    with op.batch_alter_table('schools', schema=None) as batch_op:
        batch_op.drop_column('reg_payment_status')

    # ### end Alembic commands ###
