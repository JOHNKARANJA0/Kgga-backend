#!/usr/bin/env python3

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
from sqlalchemy import MetaData, func
from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import Bcrypt
import uuid

bcrypt = Bcrypt()

metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)

class BaseModel(db.Model):
    __abstract__ = True
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

class User(BaseModel, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    image = db.Column(db.String(255))
    phone_number = db.Column(db.String(20), nullable=False)
    roles = db.Column(db.String(20), nullable=False)
    _password_hash = db.Column(db.String(128), nullable=False)
    token = db.Column(db.String(32), nullable=True)
    membership_no = db.Column(db.Integer, nullable=False, default=0)
    token_verified = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)

    events = relationship('Event', back_populates='organizer', cascade='all, delete-orphan')

    @validates('email')
    def validate_email(self, key, value):
        if '@' not in value:
            raise ValueError("Invalid email provided")
        return value

    @validates('phone_number')
    def validate_phone_number(self, key, value):
        if not value.isdigit() or len(value) != 10:
            raise ValueError("Invalid Kenyan phone number")
        return value

    @hybrid_property    
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password cannot be empty")
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    serialize_rules = ('-_password_hash', '-events')

class Student(BaseModel, SerializerMixin):
    __tablename__ = 'students'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)  # Date of birth
    category = db.Column(db.String(20), nullable=False)  # "rainbows", "brownies", "girl_guides", "rangers"
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=False)  # School the student is associated with
    parentName = db.Column(db.String(100), nullable= True)
    parentPhone = db.Column(db.String(100), nullable= True)
    membership_no = db.Column(db.Integer, nullable=False, default=0)
    
    # Relationships
    school = relationship('School', back_populates='students')
    @property
    def age(self):
        # Get the current date
        today = self._get_current_date()
        
        # Check if dob is None or not a date instance
        if self.dob is None:
            raise ValueError("Date of birth must not be None.")
        if not isinstance(self.dob, date):
            raise TypeError(f"Expected a date instance for dob, got {type(self.dob)}.")

        # Calculate age
        age = today.year - self.dob.year - ((today.month, today.day) < (self.dob.month, self.dob.day))
        return age

    @staticmethod
    def _get_current_date():
        return date.today()

    def update_category(self):
        age = self.age
        if 5 <= age <= 7:
            self.category = "rainbows"
        elif 8 <= age <= 10:
            self.category = "brownies"
        elif 11 <= age <= 14:
            self.category = "girl_guides"
        elif 15 <= age <= 17:
            self.category = "rangers"

    serialize_rules = ('-school',)


class Youth(BaseModel, SerializerMixin):
    __tablename__ = 'youths'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    _password_hash = db.Column(db.String(128), nullable=False)
    roles = db.Column(db.String(128), nullable=True)
    dob = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(20), nullable=False, default='Young_Leader')
    email = db.Column(db.String(100), unique=True, nullable=False)
    image = db.Column(db.String(255))
    membership_no = db.Column(db.Integer, nullable=False,default=0)
    phone_number = db.Column(db.String(20), nullable=False)
    token = db.Column(db.String(32), nullable=True)
    
    registration_fee = db.Column(db.Float, default=500.0)
    yearly_payment_amount = db.Column(db.Float, default=500.0)
    last_payment_date = db.Column(db.DateTime)
    payment_status = db.Column(db.String(20), default='unpaid')
    is_active = db.Column(db.Boolean, default=False)
    
    schools = relationship('School', back_populates='guide_leader')
    payments = relationship('Payment', back_populates='youth', cascade='all, delete-orphan')

    def update_payment_status(self):
        current_year = datetime.now().year
        
        paid_amount = db.session.query(func.sum(Payment.amount))\
            .filter(Payment.youth_id == self.id,
                   Payment.payment_type == 'yearly',
                   Payment.status == 'completed',
                   Payment.payment_year == current_year)\
            .scalar() or 0.0

        self.yearly_payment_amount = 500 - paid_amount
        self.last_payment_date = datetime.now()
        
        if paid_amount >= 500.0:
            self.payment_status = 'paid'
        elif paid_amount > 0:
            self.payment_status = 'partial'
        else:
            self.payment_status = 'unpaid'


    @validates('phone_number')
    
    def validate_phone_number(self, key, value):
        if not value.isdigit() or len(value) != 10:
            raise ValueError("Invalid Kenyan phone number")
        return value
    
    @validates('dob')
    def validate_dob(self, key, dob_value):
        # Ensure date of birth is not None
        if dob_value is None:
            raise ValueError("Date of birth must not be None.")

        # Ensure dob is a date instance
        if not isinstance(dob_value, date):
            raise TypeError(f"Expected a date instance for dob, got {type(dob_value)}.")
        
        # # Validate age range
        # age = self.age
        # if age < 18 or age > 25:  # Define the age range for youths
        #     raise ValueError("Youth age must be between 18 and 25 years")
        
        return dob_value
    @property
    def age(self):
        # Get the current date
        today = self._get_current_date()

        # Check if dob is None or not a date instance
        if self.dob is None:
            raise ValueError("Date of birth must not be None.")
        if not isinstance(self.dob, date):
            raise TypeError(f"Expected a date instance for dob, got {type(self.dob)}.")

        # Calculate age
        age = today.year - self.dob.year - ((today.month, today.day) < (self.dob.month, self.dob.day))
        return age

    @staticmethod
    def _get_current_date():
        return date.today()

    def update_category(self):
        """Update category based on age."""
        age = self.age
        if 18 <= age < 30:
            self.category = "Young_Leader"
        elif 30 <= age <= 50:
            self.category = "Bravo"
    @hybrid_property    
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password cannot be empty")
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    serialize_rules = ('-schools', '-payments.youth', '-_password_hash', 
                       'payments.id', 'payments.payment_method', 'payments.amount', 
                       'payments.payment_date', 'payments.status', 
                       'payments.school_id', 'payments.created_at', 'payments.updated_at', '-age')

class School(BaseModel, SerializerMixin):
    __tablename__ = 'schools'

    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String(100), nullable=False)
    _password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    county = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(32), nullable=True)
    headteacher_name = db.Column(db.String(100))
    school_type = db.Column(db.String(20))
    membership_no = db.Column(db.Integer, nullable=False, default=0)
    registration_date = db.Column(db.DateTime, default=db.func.now())
    guide_leader_id = db.Column(db.Integer, db.ForeignKey('youths.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=False)

    yearly_payment_amount = db.Column(db.Float, default=0.0)
    last_payment_date = db.Column(db.DateTime)
    payment_status = db.Column(db.String(20), default='unpaid')
    registration_fee = db.Column(db.Float, default=1000.0)

    financial_reports = relationship("FinancialReport", back_populates="school")
    events = relationship('Event', back_populates='school', cascade='all, delete-orphan')
    guide_leader = relationship('Youth', back_populates='schools', foreign_keys=[guide_leader_id])
    students = relationship('Student', back_populates='school')
    payments = relationship('Payment', back_populates='school', cascade='all, delete-orphan')

    serialize_rules = ('-payments.school', '-guide_leader.payments', '-_password_hash', '-events')

    def calculate_yearly_payment(self):
        return len(self.students) * 200.0

    def update_payment_status(self):
        yearly_total = self.calculate_yearly_payment()
        self.yearly_payment_amount = self.calculate_yearly_payment()
        current_year = datetime.now().year
        
        paid_amount = db.session.query(func.sum(Payment.amount))\
            .filter(Payment.school_id == self.id,
                   Payment.payment_type == 'yearly',
                   Payment.status == 'completed',
                   Payment.payment_year == current_year)\
            .scalar() or 0.0

        self.yearly_payment_amount = yearly_total - paid_amount
        self.last_payment_date = datetime.now()
        
        if paid_amount >= yearly_total:
            self.payment_status = 'paid'
        elif paid_amount > 0:
            self.payment_status = 'partial'
        else:
            self.payment_status = 'unpaid'


    def calculate_total_subscription(self):
        subscription_amount = 200.0  # Subscription amount
        return len(self.students) * subscription_amount
    
    @validates('email')
    def validate_email(self, key, value):
        if '@' not in value:
            raise ValueError("Invalid email provided")
        return value

    @validates('phone_number')
    def validate_phone_number(self, key, value):
        if not value.isdigit() or len(value) != 10:
            raise ValueError("Invalid Kenyan phone number")
        return value

    @hybrid_property    
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password cannot be empty")
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)
class Payment(BaseModel, SerializerMixin):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    payment_date = db.Column(db.DateTime, default=datetime.now)
    payment_method = db.Column(db.String(20), default='mpesa')
    
    transaction_id = db.Column(db.String(50), unique=True)
    phone_number = db.Column(db.String(20))
    mpesa_receipt_number = db.Column(db.String(50), unique=True)
    
    payment_type = db.Column(db.String(20), nullable=False)
    payment_year = db.Column(db.Integer, default=lambda: datetime.now().year)
    
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True)
    youth_id = db.Column(db.Integer, db.ForeignKey('youths.id'), nullable=True)

    school = relationship('School', back_populates='payments')
    youth = relationship('Youth', back_populates='payments')
    

    @validates('payment_type')
    def validate_payment_type(self, key, value):
        if value not in ['registration', 'yearly']:
            raise ValueError("Payment type must be either 'registration' or 'yearly'")
        return value

    def generate_transaction_id(self):
        return f"TXN-{uuid.uuid4().hex[:8].upper()}"

    @validates('status')
    def validate_status(self, key, value):
        if value not in ['pending', 'completed', 'failed']:
            raise ValueError("Invalid payment status")
        return value

    def process_payment(self):
        """Process the payment and update related models"""
        if self.status == 'completed':
            if self.school_id:
                self.school.update_payment_status()
            elif self.youth_id:
                self.youth.update_payment_status()

    @validates('youth_id', 'school_id')
    def validate_payment_relationship(self, key, value):
        if key == 'youth_id' and value is not None and self.school_id is not None:
            raise ValueError("Payment cannot be linked to both user and school.")
        return value

    def total_payment_due(self, youth):
        """Calculate total payment due for a youth, including registration fee and yearly payment."""
        return youth.registration_fee + youth.yearly_payment
    
class Event(BaseModel, SerializerMixin):
    __tablename__ = 'events'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    #image = db.Column(db.String, nullable=True)
    description = db.Column(db.Text)
    event_date = db.Column(db.Date, nullable=False)
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=False)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # User organizing the event

    school = relationship('School', back_populates='events')
    organizer = relationship('User', back_populates='events')

    @validates('event_date')
    def validate_event_date(self, key, event_date_value):
        if event_date_value < datetime.now().date():
            raise ValueError("Event date must be in the future.")
        return event_date_value

    serialize_rules = ('-school', '-organizer')

class FinancialReport(BaseModel, SerializerMixin):
    __tablename__ = 'financial_reports'

    id = db.Column(db.Integer, primary_key=True)
    report_date = db.Column(db.Date, default=db.func.now())
    total_income = db.Column(db.Float, nullable=False)
    total_expenditure = db.Column(db.Float, nullable=False)
    net_profit = db.Column(db.Float, nullable=False)

    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=False)

    school = relationship('School', back_populates='financial_reports')

    serialize_rules = ('-school',)
    @classmethod
    def generate_report(cls, start_date, end_date):
        """
        Generate a financial report for a given date range.
        
        Args:
            start_date (date): The start date for the report.
            end_date (date): The end date for the report.

        Returns:
            dict: A dictionary containing the total income, total expenditure, and net profit.
        """
        # Query to sum up the total income and expenditure within the given date range
        results = db.session.query(
            db.func.sum(cls.total_income).label('total_income'),
            db.func.sum(cls.total_expenditure).label('total_expenditure'),
        ).filter(
            cls.report_date >= start_date,
            cls.report_date <= end_date
        ).one_or_none()

        if results is None:
            return {
                "total_income": 0,
                "total_expenditure": 0,
                "net_profit": 0,
            }

        total_income = results.total_income if results.total_income is not None else 0
        total_expenditure = results.total_expenditure if results.total_expenditure is not None else 0
        net_profit = total_income - total_expenditure

        return {
            "total_income": total_income,
            "total_expenditure": total_expenditure,
            "net_profit": net_profit,
        }

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(120), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_expired(self):
        return datetime.now() > self.expires_at

# Helper function to update student and youth categories
def update_student_categories():
    students = Student.query.all()
    for student in students:
        student.update_category()
        db.session.commit()

def update_youth_categories():
    youths = Youth.query.all()
    for youth in youths:
        youth.update_category()
        db.session.commit()

# Financial Report Example Usage
def generate_financial_report():
    start_date = datetime.now() - timedelta(days=1000)  # Last 30 days
    end_date = datetime.now()
    report = FinancialReport.generate_report(start_date, end_date)
    return report

def update_completed_payments():
    """Helper function to process all completed payments for both Youth and School."""
    # Retrieve payments with status 'completed' that need processing
    completed_payments = Payment.query.filter_by(status='completed').all()
    
    for payment in completed_payments:
        payment.process_payment()
    
    # Commit any updates made by process_payment
    db.session.commit()

