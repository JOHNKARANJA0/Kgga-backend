"""Initial Migration

Revision ID: 148eca7c62c8
Revises: 9faef8cf0240
Create Date: 2024-10-21 11:13:04.145442

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '148eca7c62c8'
down_revision = '9faef8cf0240'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('image', sa.String(length=255), nullable=True),
    sa.Column('phone_number', sa.String(length=20), nullable=False),
    sa.Column('roles', sa.String(length=20), nullable=False),
    sa.Column('_password_hash', sa.String(length=128), nullable=False),
    sa.Column('token', sa.String(length=32), nullable=True),
    sa.Column('token_verified', sa.Boolean(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('membership_renewal_status', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('youths',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('_password_hash', sa.String(length=128), nullable=False),
    sa.Column('roles', sa.String(length=128), nullable=True),
    sa.Column('dob', sa.Date(), nullable=False),
    sa.Column('category', sa.String(length=20), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('image', sa.String(length=255), nullable=True),
    sa.Column('phone_number', sa.String(length=20), nullable=False),
    sa.Column('token', sa.String(length=32), nullable=True),
    sa.Column('registration_fee', sa.Float(), nullable=True),
    sa.Column('yearly_payment', sa.Float(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('schools',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('school_name', sa.String(length=100), nullable=False),
    sa.Column('_password_hash', sa.String(length=128), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('phone_number', sa.String(length=20), nullable=False),
    sa.Column('county', sa.String(length=50), nullable=False),
    sa.Column('token', sa.String(length=32), nullable=True),
    sa.Column('headteacher_name', sa.String(length=100), nullable=True),
    sa.Column('school_type', sa.String(length=20), nullable=True),
    sa.Column('registration_date', sa.DateTime(), nullable=True),
    sa.Column('guide_leader_id', sa.Integer(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['guide_leader_id'], ['youths.id'], name=op.f('fk_schools_guide_leader_id_youths')),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('event_date', sa.Date(), nullable=False),
    sa.Column('school_id', sa.Integer(), nullable=False),
    sa.Column('organizer_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['organizer_id'], ['users.id'], name=op.f('fk_events_organizer_id_users')),
    sa.ForeignKeyConstraint(['school_id'], ['schools.id'], name=op.f('fk_events_school_id_schools')),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('financial_reports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('report_date', sa.Date(), nullable=True),
    sa.Column('total_income', sa.Float(), nullable=False),
    sa.Column('total_expenditure', sa.Float(), nullable=False),
    sa.Column('net_profit', sa.Float(), nullable=False),
    sa.Column('school_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['school_id'], ['schools.id'], name=op.f('fk_financial_reports_school_id_schools')),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('payments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=True),
    sa.Column('payment_date', sa.Date(), nullable=True),
    sa.Column('payment_method', sa.String(length=20), nullable=True),
    sa.Column('school_id', sa.Integer(), nullable=True),
    sa.Column('youth_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['school_id'], ['schools.id'], name=op.f('fk_payments_school_id_schools')),
    sa.ForeignKeyConstraint(['youth_id'], ['youths.id'], name=op.f('fk_payments_youth_id_youths')),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('students',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('dob', sa.Date(), nullable=False),
    sa.Column('category', sa.String(length=20), nullable=False),
    sa.Column('school_id', sa.Integer(), nullable=False),
    sa.Column('parentName', sa.String(length=100), nullable=True),
    sa.Column('parentPhone', sa.String(length=100), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['school_id'], ['schools.id'], name=op.f('fk_students_school_id_schools')),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('students')
    op.drop_table('payments')
    op.drop_table('financial_reports')
    op.drop_table('events')
    op.drop_table('schools')
    op.drop_table('youths')
    op.drop_table('users')
    # ### end Alembic commands ###
