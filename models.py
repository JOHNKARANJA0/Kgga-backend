from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates, relationship, backref
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import Bcrypt
from datetime import datetime

bcrypt = Bcrypt()

metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)

class BaseModel(db.Model):
    __abstract__ = True
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class User(BaseModel, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    image = db.Column(db.String(255))
    phone_number = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    _password_hash = db.Column(db.String(128), nullable=False)
    token = db.Column(db.String(32))
    token_verified = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    membership_renewal_status = db.Column(db.String(20))
    
    # Subscription details
    subscription_amount = db.Column(db.Float, default=200.0)  # Subscription amount
    subscription_date = db.Column(db.Date)  # Date of subscription payment

    units = relationship('Unit', back_populates='guide', cascade='all, delete-orphan')
    schools = relationship('School', back_populates='guide', cascade='all, delete-orphan')
    students = relationship('Student', back_populates='guide', cascade='all, delete-orphan')
    payments = relationship('Payment', back_populates='user', cascade='all, delete-orphan')

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

    serialize_rules = ('-_password_hash', '-units', '-schools', '-students', '-payments')

class Student(BaseModel, SerializerMixin):
    __tablename__ = 'students'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey('units.id'))
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))
    guide_leader_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    membership_status = db.Column(db.String(10))

    unit = relationship('Unit', back_populates='students', single_parent=True)
    school = relationship('School', back_populates='students', single_parent=True)
    guide = relationship('User', back_populates='students')
    events = relationship('Event', secondary='student_events', back_populates='students')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'membership_status': self.membership_status,
            'school': self.school.school_name if self.school else None, 
            'school_headteacher': self.school.headteacher_name if self.school else None, 
            'unit_name': self.unit.unit_name if self.unit else None,  
            'guide_leader_name': self.guide.name if self.guide else None,
        }

    @validates('age')
    def validate_age(self, key, value):
        if value < 5 or value > 50:
            raise ValueError("Age must be between 5 and 50")
        return value

class Unit(BaseModel, SerializerMixin):
    __tablename__ = 'units'
    
    id = db.Column(db.Integer, primary_key=True)
    unit_name = db.Column(db.String(50), nullable=False)
    min_age = db.Column(db.Integer, nullable=False)
    max_age = db.Column(db.Integer, nullable=False)
    guide_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    guide = relationship('User', back_populates='units')
    students = relationship('Student', back_populates='unit')  
    reports = relationship('Report', back_populates='unit')

    serialize_rules = ('-guide', '-students', '-reports')

class School(BaseModel, SerializerMixin):
    __tablename__ = 'schools'
    
    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String(100), nullable=False)
    county = db.Column(db.String(50), nullable=False)
    headteacher_name = db.Column(db.String(100))
    school_type = db.Column(db.String(20))
    registration_date = db.Column(db.Date)
    guide_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    guide = relationship('User', back_populates='schools')
    students = relationship('Student', back_populates='school') 
    events = relationship('Event', back_populates='school')
    reports = relationship('Report', back_populates='school')
    payments = relationship('Payment', back_populates='school', cascade='all, delete-orphan')

    serialize_rules = ('-guide', '-students', '-events', '-reports', '-payments')

    @property
    def student_count(self):
        return len(self.students)
    
    def calculate_total_subscription(self):
        # Assuming each student contributes a fixed subscription amount
        subscription_amount = 200.0  # You can adjust this value or make it dynamic
        return self.student_count * subscription_amount

    @property
    def total_subscription_fees(self):
        return self.student_count * 200
    
    def to_dict(self):
        return {
            'id': self.id,
            'school_name': self.school_name,
            'headteacher_name': self.headteacher_name,
            'total_subscription_due': self.calculate_total_subscription(),
            'students_count': len(self.students),
            'school_type': self.school_type,
            'county': self.county,
            'registration_date': self.registration_date.strftime('%Y-%m-%d') if self.registration_date else None,
            'guide_id': self.guide.name if self.guide else None,
        }

class Event(BaseModel, SerializerMixin):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(100), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    event_type = db.Column(db.String(50))  
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))

    school = relationship('School', back_populates='events')
    students = relationship('Student', secondary='student_events', back_populates='events')

    serialize_rules = ('-school', '-students')

class StudentEvent(BaseModel, SerializerMixin):
    __tablename__ = 'student_events'
    
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), primary_key=True)

class Payment(BaseModel, SerializerMixin):
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Nullable for user
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'), nullable=True)  # Nullable for school
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(10))
    payment_date = db.Column(db.Date)
    payment_method = db.Column(db.String(20))

    user = relationship('User', back_populates='payments')
    school = relationship('School', back_populates='payments')

    @validates('user_id', 'school_id')
    def validate_payment_relationship(self, key, value):
        if key == 'user_id' and value is not None and self.school_id is not None:
            raise ValueError("Payment cannot be linked to both user and school.")
        if key == 'school_id' and value is not None and self.user_id is not None:
            raise ValueError("Payment cannot be linked to both user and school.")
        return value


class Report(BaseModel, SerializerMixin):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))
    unit_id = db.Column(db.Integer, db.ForeignKey('units.id'))
    total_membership_fees_collected = db.Column(db.Float)
    report_date = db.Column(db.Date)
    report_type = db.Column(db.String(50))

    school = relationship('School', back_populates='reports')
    unit = relationship('Unit', back_populates='reports')

    serialize_rules = ('-school', '-unit')

class PaymentReminder(BaseModel, SerializerMixin):
    __tablename__ = 'payment_reminders'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'))
    reminder_date = db.Column(db.Date)
    reminder_type = db.Column(db.String(20))  
    status = db.Column(db.String(20))  

    student = relationship('Student', backref='payment_reminders')

    def to_dict(self):
        return {
            "id": self.id,
            "student_id": self.student_id,
            "reminder_date": self.reminder_date.strftime('%Y-%m-%d') if self.reminder_date else None,
            "reminder_type": self.reminder_type,
            "status": self.status,
            "student_name": self.student.name if self.student else None
        }

class AgeTransitionNotification(BaseModel, SerializerMixin):
    __tablename__ = 'age_transition_notifications'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'))
    from_unit = db.Column(db.String(50))
    to_unit = db.Column(db.String(50))
    notification_date = db.Column(db.Date)
    age_transition_status = db.Column(db.String(20))
    status = db.Column(db.String(20))

    student = relationship('Student', backref='notifications')

    def to_dict(self):
        return {
            "id": self.id,
            "student_id": self.student_id,
            'from_unit': self.from_unit,
            'to_unit': self.to_unit,
            'status': self.status,
            "notification_date": self.notification_date.strftime('%Y-%m-%d') if self.notification_date else None,
            "age_transition_status": self.age_transition_status,
            "student_name": self.student.name if self.student else None
        }
