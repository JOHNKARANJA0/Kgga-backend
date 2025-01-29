#!/usr/bin/env python3

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from sqlalchemy import MetaData, func
from pytz import timezone
from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import Bcrypt
from sqlalchemy.ext.declarative import declared_attr
import uuid

bcrypt = Bcrypt()

metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)
nairobi_tz = timezone('Africa/Nairobi')
class BaseModel(db.Model):
    __abstract__ = True
    @declared_attr
    def created_at(cls):
        return db.Column(
            db.DateTime,
            default=lambda: datetime.now(nairobi_tz)
        )

    @declared_attr
    def updated_at(cls):
        return db.Column(
            db.DateTime,
            default=lambda: datetime.now(nairobi_tz),
            onupdate=lambda: datetime.now(nairobi_tz)
        )

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


def start_of_creation_year():
    """
    Return the start of the current year (January 1st).
    """
    now = datetime.now(nairobi_tz)
    return datetime(now.year, 1, 1)

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
    registration_fee_default = db.Column(db.Float, default=500.0)
    yearly_payment_amount = db.Column(db.Float, default=500.0)
    yearly_total_payment = db.Column(db.Float, default=500.0)
    last_payment_date = db.Column(db.DateTime)
    last_updated_at = db.Column(db.DateTime, default=datetime.now(nairobi_tz))
    payment_status = db.Column(db.String(20), default='unpaid')
    reg_payment_status = db.Column(db.String(20), default='unpaid')
    is_active = db.Column(db.Boolean, default=False)
    commissioner = db.Column(db.String(20), nullable=True)
    commitee = db.Column(db.String(20), nullable=True)
    attendances = relationship('Attendance', back_populates='youth', cascade='all, delete-orphan')
    schools = relationship('School', back_populates='guide_leader')
    payments = relationship('Payment', back_populates='youth', cascade='all, delete-orphan')
    def update_youth_amounts(self):
        if any(school.guide_leader == self.name for school in self.schools):
            self.registration_fee = 500.0  # If guide_leader, set appropriate fee
            self.yearly_payment_amount = 500.0
            self.yearly_total_payment=500.0
            self.registration_fee_default= 500.0
        else:
            # Handle Bravo category if the school is not a guide_leader
            if self.category == 'Bravo' or self.commitee is not None:
                self.registration_fee = 1000.0
                self.yearly_payment_amount = 1000.0
                self.yearly_total_payment=1000.0
                self.registration_fee_default= 1000.0
            else:
                self.registration_fee = 500.0  # Default category
                self.yearly_payment_amount = 500.0
                self.yearly_total_payment=500.0
                self.registration_fee_default= 500.0
                
    def update_payment_status(self):
        current_year = datetime.now(nairobi_tz).year
        
        paid_amount = db.session.query(func.sum(Payment.amount))\
            .filter(Payment.youth_id == self.id,
                   Payment.payment_type == 'yearly',
                   Payment.status == 'completed',
                   Payment.payment_year == current_year)\
            .scalar() or 0.0
        remaining_yearly_payment = self.yearly_payment_amount - paid_amount
        self.yearly_payment_amount = max(remaining_yearly_payment, 0.0)
        self.last_payment_date = datetime.now(nairobi_tz)
        
        if paid_amount >= self.yearly_total_payment:
            self.payment_status = 'paid'
        elif paid_amount > 0:
            self.payment_status = 'partial'
        else:
            self.payment_status = 'unpaid'
        
            
        reg_paid_amount = db.session.query(func.sum(Payment.amount))\
            .filter(Payment.youth_id == self.id,
                   Payment.payment_type == 'registration',
                   Payment.status == 'completed')\
            .scalar() or 0.0
        remaining_registration_fee = self.registration_fee - reg_paid_amount
        remaining_registration_fee = max(remaining_registration_fee, 0.0) 
        self.registration_fee = remaining_registration_fee 
        if reg_paid_amount >= self.registration_fee_default:
            self.reg_payment_status = 'paid'
        elif reg_paid_amount > 0:
            self.reg_payment_status = 'partial'
        else:
            self.reg_payment_status = 'unpaid'
        
        if self.payment_status == 'paid' and self.reg_payment_status == 'paid':
            self.is_active = True
        else:
            self.is_active= False


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
                       'payments.school_id', 'payments.created_at', 'payments.updated_at', '-age', '-attendances')

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
    membership_no = db.Column(db.Integer, nullable=True, default=0)
    registration_date = db.Column(db.DateTime, default=db.func.now())
    guide_leader_id = db.Column(db.Integer, db.ForeignKey('youths.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    yearly_payment_amount = db.Column(db.Float, default=0.0)
    last_payment_date = db.Column(db.DateTime)
    last_updated_at = db.Column(db.DateTime, default=datetime.now(nairobi_tz))
    payment_status = db.Column(db.String(20), default='unpaid')
    reg_payment_status = db.Column(db.String(20), default='unpaid')
    registration_fee = db.Column(db.Float, default=500.0)
    registration_fee_total = db.Column(db.Float, default=500.0)
    yearly_total_payment = db.Column(db.Float, default=0.0)
    guide_leader = relationship('Youth', back_populates='schools', foreign_keys=[guide_leader_id])
    students = relationship('Student', back_populates='school')
    payments = relationship('Payment', back_populates='school', cascade='all, delete-orphan')
    attendances = relationship('Attendance', back_populates='school', cascade='all, delete-orphan')
    
    serialize_rules = ('-payments.school', '-guide_leader.payments', '-_password_hash', '-attendances')
    @hybrid_property
    def calculated_yearly_payment(self):
        """Dynamically calculate the yearly payment based on the number of students and school type."""
        
        # Determine the base amount depending on the school type
        if self.school_type == 'Public':
            amount_per_student = 50.0  # Amount for public schools
        elif self.school_type == 'Private':
            amount_per_student = 100.0  # Amount for private schools
        else:
            amount_per_student = 100.0 
        
        # Calculate the total yearly payment
        return 500 + (len(self.students) * amount_per_student)
    @hybrid_property
    def calculated_regist_payment(self):
        """Dynamically calculate the yearly payment based on the number of students and school type."""
        
        # Determine the base amount depending on the school type
        if self.school_type == 'Public':
            amount_student = 50.0  # Amount for public schools
        elif self.school_type == 'Private':
            amount_student = 100.0  # Amount for private schools
        else:
            amount_student = 100.0 
        
        # Calculate the total yearly payment
        return 500 + (len(self.students) * amount_student)

    def set_yearly_payment(self):
        """Pre-calculate and set yearly payment fields."""
        yearly_total = self.calculated_yearly_payment
        reg_total = self.calculated_regist_payment
        self.yearly_total_payment = yearly_total
        self.yearly_payment_amount = yearly_total
        self.registration_fee = reg_total
        self.registration_fee_total = reg_total
        
    def update_payment_status(self):
        current_year = datetime.now(nairobi_tz).year
        
        paid_amount = db.session.query(func.sum(Payment.amount))\
            .filter(Payment.school_id == self.id,
                   Payment.payment_type == 'yearly',
                   Payment.status == 'completed',
                   Payment.payment_year == current_year)\
            .scalar() or 0.0

        self.yearly_payment_amount = max(self.yearly_total_payment - paid_amount, 0.0)
        self.last_payment_date = datetime.now(nairobi_tz)
        
        if paid_amount >= self.yearly_total_payment:
            self.payment_status = 'paid'
        elif paid_amount > 0:
            self.payment_status = 'partial'
        else:
            self.payment_status = 'unpaid'

        
        reg_paid_amount = db.session.query(func.sum(Payment.amount))\
            .filter(Payment.school_id == self.id,
                   Payment.payment_type == 'registration',
                   Payment.status == 'completed')\
            .scalar() or 0.0
        self.registration_fee = max(self.registration_fee_total - reg_paid_amount, 0)
        if reg_paid_amount >= self.registration_fee_total:
            self.reg_payment_status = 'paid'
        elif reg_paid_amount > 0:
            self.reg_payment_status = 'partial'
        else:
            self.reg_payment_status = 'unpaid'
        
        if self.payment_status == 'paid' and self.reg_payment_status == 'paid':
            self.is_active = True
        else:
            self.is_active = False
        
    
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
    payment_date = db.Column(db.DateTime, default=datetime.now(nairobi_tz))
    payment_method = db.Column(db.String(20), default='mpesa')
    merchant_request_id = db.Column(db.String(50), unique=True)
    transaction_id = db.Column(db.String(50), unique=True)
    phone_number = db.Column(db.String(20))
    mpesa_receipt_number = db.Column(db.String(50), unique=True)
    
    payment_type = db.Column(db.String(20), nullable=False)
    payment_year = db.Column(db.Integer, default=lambda: datetime.now(nairobi_tz).year)
    
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True)
    youth_id = db.Column(db.Integer, db.ForeignKey('youths.id'), nullable=True)

    school = relationship('School', back_populates='payments')
    youth = relationship('Youth', back_populates='payments')
    

    @validates('payment_type')
    def validate_payment_type(self, key, value):
        if value not in ['registration', 'yearly']:
            raise ValueError("Payment type must be either 'registration' or 'yearly'")
        return value

    @staticmethod
    def generate_transaction_id():
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
    image = db.Column(db.String, nullable=True)
    description = db.Column(db.Text)
    category = db.Column(db.String, nullable=True)
    event_date = db.Column(db.DateTime, nullable=False)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    organizer = relationship('User', back_populates='events')
    attendances = relationship('Attendance', back_populates='event', cascade='all, delete-orphan')
    serialize_rules = ('-attendances',)
    @validates('event_date')
    def validate_event_date(self, key, event_date):
        # Parse `event_date` to a date object if it's a string
        if isinstance(event_date, str):
            event_date = datetime.strptime(event_date, '%Y-%m-%dT%H:%M')
        
        if event_date < datetime.now(nairobi_tz):
            raise ValueError("Event date must be in the future.")
        
        return event_date
    @hybrid_property
    def attendance_details(self):
        """
        Returns attendance details with school or youth-specific information.
        """
        details = []
        for attendance in self.attendances:
            if attendance.school_id:
                details.append({
                    "school_id": attendance.school_id,
                    "school_name": attendance.school.school_name,
                    "school_email": attendance.school.email
                })
            elif attendance.youth_id:
                details.append({
                    "youth_id": attendance.youth_id,
                    "youth_name": attendance.youth.name
                })
        return details
    def to_dict(self):
        """
        Converts the Event instance to a dictionary, including attendance details.
        """
        event_dict = super().to_dict()
        event_dict['attendance_details'] = self.attendance_details
        return event_dict

class Attendance(BaseModel, SerializerMixin):
    __tablename__ = 'attendances'

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    youth_id = db.Column(db.Integer, db.ForeignKey('youths.id'), nullable=True)
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True)
    attendance_date = db.Column(db.DateTime, default=datetime.now(nairobi_tz))

    # Establish relationships
    event = relationship('Event', back_populates='attendances')
    youth = relationship('Youth', back_populates='attendances')
    school = relationship('School', back_populates='attendances')

    # Ensure that either youth or school is assigned to this attendance, not both
    @validates('youth_id', 'school_id')
    def validate_attendance(self, key, value):
        if key == 'youth_id' and self.school_id:
            raise ValueError("Cannot assign both youth and school to the same attendance.")
        if key == 'school_id' and self.youth_id:
            raise ValueError("Cannot assign both youth and school to the same attendance.")
        return value


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(120), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_expired(self):
        return datetime.now(nairobi_tz) > self.expires_at

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



def update_completed_payments():
    """Helper function to process all completed payments for both Youth and School."""
    # Retrieve payments with status 'completed' that need processing
    completed_payments = Payment.query.filter_by(status='completed').all()

    for payment in completed_payments:
        payment.process_payment()
    
    # Commit any updates made by process_payment
    db.session.commit()

