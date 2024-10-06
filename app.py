#!/usr/bin/env python3
import os
from datetime import timedelta
import pyotp
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, User, Student, Unit, School, Event, Payment, Report, PaymentReminder, AgeTransitionNotification, bcrypt
from utils import generate_totp_secret, generate_totp_token, send_email

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}})

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI') #'sqlite:///app.db'
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "your_secret_key"

app.json.compact = False
jwt = JWTManager(app)

migrate = Migrate(app, db)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)


@app.route("/")
def index():
    return "<h1>KGGA SERVER</h1>"

# Authentication Routes
class Login(Resource):
    def post(self):
        request_json = request.get_json()
        email = request_json.get('email', None)
        password = request_json.get('password', None)

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            user.is_active = True
            db.session.commit()
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
        else:
            return {"message": "Invalid email or password"}, 401

class CheckSession(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if user:
            return user.to_dict(), 200
        else:
            return {"error": "User not found"}, 404

BLACKLIST = set()
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, decrypted_token):
    return decrypted_token['jti'] in BLACKLIST

class Logout(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if user:
            user.is_active = False
            db.session.commit()
        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"success": "Successfully logged out"}, 200

# User resource for CRUD operations
class UserResource(Resource):
    def get(self, user_id=None):
        if user_id:
            user = User.query.get_or_404(user_id)
            return user.to_dict()
        else:
            users = User.query.all()
            return [user.to_dict() for user in users]

    def post(self):
        data = request.get_json()
        new_user = User(
            name=data['name'],
            email=data['email'],
            phone_number=data['phone_number'],
            role=data['role'],
            password_hash=bcrypt.generate_password_hash(data['password']).decode('utf-8'),
            token=generate_totp_secret()
        )
        db.session.add(new_user)
        db.session.commit()
        return new_user.to_dict(), 201

    def put(self, user_id):
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(user, key, value)
        db.session.commit()
        return user.to_dict()

    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return '', 204

# Student resource for CRUD operations
class StudentResource(Resource):
    def get(self, student_id=None):
        if student_id:
            student = Student.query.get_or_404(student_id)
            return student.to_dict()
        else:
            students = Student.query.all()
            return [student.to_dict() for student in students]

    def post(self):
        data = request.get_json()
        new_student = Student(**data)
        db.session.add(new_student)
        db.session.commit()
        return new_student.to_dict(), 201

    def put(self, student_id):
        student = Student.query.get_or_404(student_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(student, key, value)
        db.session.commit()
        return student.to_dict()

    def delete(self, student_id):
        student = Student.query.get_or_404(student_id)
        db.session.delete(student)
        db.session.commit()
        return '', 204

# Unit resource for CRUD operations
class UnitResource(Resource):
    def get(self, unit_id=None):
        if unit_id:
            unit = Unit.query.get_or_404(unit_id)
            return unit.to_dict()
        else:
            units = Unit.query.all()
            return [unit.to_dict() for unit in units]

    def post(self):
        data = request.get_json()
        new_unit = Unit(**data)
        db.session.add(new_unit)
        db.session.commit()
        return new_unit.to_dict(), 201

    def put(self, unit_id):
        unit = Unit.query.get_or_404(unit_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(unit, key, value)
        db.session.commit()
        return unit.to_dict()

    def delete(self, unit_id):
        unit = Unit.query.get_or_404(unit_id)
        db.session.delete(unit)
        db.session.commit()
        return '', 204

# School resource for CRUD operations
class SchoolResource(Resource):
    def get(self, school_id=None):
        if school_id:
            school = School.query.get_or_404(school_id)
            return school.to_dict()
        else:
            schools = School.query.all()
            return [school.to_dict() for school in schools]

    def post(self):
        data = request.get_json()
        new_school = School(**data)
        db.session.add(new_school)
        db.session.commit()
        return new_school.to_dict(), 201

    def put(self, school_id):
        school = School.query.get_or_404(school_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(school, key, value)
        db.session.commit()
        return school.to_dict()

    def delete(self, school_id):
        school = School.query.get_or_404(school_id)
        db.session.delete(school)
        db.session.commit()
        return '', 204

# Event resource for CRUD operations
class EventResource(Resource):
    def get(self, event_id=None):
        if event_id:
            event = Event.query.get_or_404(event_id)
            return event.to_dict()
        else:
            events = Event.query.all()
            return [event.to_dict() for event in events]

    def post(self):
        data = request.get_json()
        new_event = Event(**data)
        db.session.add(new_event)
        db.session.commit()
        return new_event.to_dict(), 201

    def put(self, event_id):
        event = Event.query.get_or_404(event_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(event, key, value)
        db.session.commit()
        return event.to_dict()

    def delete(self, event_id):
        event = Event.query.get_or_404(event_id)
        db.session.delete(event)
        db.session.commit()
        return '', 204

# Payment resource for CRUD operations
class PaymentResource(Resource):
    def get(self, payment_id=None):
        if payment_id:
            payment = Payment.query.get_or_404(payment_id)
            return payment.to_dict()
        else:
            payments = Payment.query.all()
            return [payment.to_dict() for payment in payments]

    def post(self):
        data = request.get_json()
        new_payment = Payment(**data)
        db.session.add(new_payment)
        db.session.commit()
        return new_payment.to_dict(), 201

    def put(self, payment_id):
        payment = Payment.query.get_or_404(payment_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(payment, key, value)
        db.session.commit()
        return payment.to_dict()

    def delete(self, payment_id):
        payment = Payment.query.get_or_404(payment_id)
        db.session.delete(payment)
        db.session.commit()
        return '', 204

# Report resource for CRUD operations
class ReportResource(Resource):
    def get(self, report_id=None):
        if report_id:
            report = Report.query.get_or_404(report_id)
            return report.to_dict()
        else:
            reports = Report.query.all()
            return [report.to_dict() for report in reports]

    def post(self):
        data = request.get_json()
        new_report = Report(**data)
        db.session.add(new_report)
        db.session.commit()
        return new_report.to_dict(), 201

    def put(self, report_id):
        report = Report.query.get_or_404(report_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(report, key, value)
        db.session.commit()
        return report.to_dict()

    def delete(self, report_id):
        report = Report.query.get_or_404(report_id)
        db.session.delete(report)
        db.session.commit()
        return '', 204

# Payment reminder resource for CRUD operations
class PaymentReminderResource(Resource):
    def get(self, reminder_id=None):
        if reminder_id:
            reminder = PaymentReminder.query.get_or_404(reminder_id)
            return reminder.to_dict()
        else:
            reminders = PaymentReminder.query.all()
            return [reminder.to_dict() for reminder in reminders]

    def post(self):
        data = request.get_json()
        new_reminder = PaymentReminder(**data)
        db.session.add(new_reminder)
        db.session.commit()
        return new_reminder.to_dict(), 201

    def put(self, reminder_id):
        reminder = PaymentReminder.query.get_or_404(reminder_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(reminder, key, value)
        db.session.commit()
        return reminder.to_dict()

    def delete(self, reminder_id):
        reminder = PaymentReminder.query.get_or_404(reminder_id)
        db.session.delete(reminder)
        db.session.commit()
        return '', 204

# Age transition notification resource
class AgeTransitionNotificationResource(Resource):
    def get(self, notification_id=None):
        if notification_id:
            notification = AgeTransitionNotification.query.get_or_404(notification_id)
            return notification.to_dict()
        else:
            notifications = AgeTransitionNotification.query.all()
            return [notification.to_dict() for notification in notifications]

    def post(self):
        data = request.get_json()
        new_notification = AgeTransitionNotification(**data)
        db.session.add(new_notification)
        db.session.commit()
        return new_notification.to_dict(), 201

    def put(self, notification_id):
        notification = AgeTransitionNotification.query.get_or_404(notification_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(notification, key, value)
        db.session.commit()
        return notification.to_dict()

    def delete(self, notification_id):
        notification = AgeTransitionNotification.query.get_or_404(notification_id)
        db.session.delete(notification)
        db.session.commit()
        return '', 204

# Routes
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')

api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(StudentResource, '/students', '/students/<int:student_id>')
api.add_resource(UnitResource, '/units', '/units/<int:unit_id>')
api.add_resource(SchoolResource, '/schools', '/schools/<int:school_id>')
api.add_resource(EventResource, '/events', '/events/<int:event_id>')
api.add_resource(PaymentResource, '/payments', '/payments/<int:payment_id>')
api.add_resource(ReportResource, '/reports', '/reports/<int:report_id>')
api.add_resource(PaymentReminderResource, '/reminders', '/reminders/<int:reminder_id>')
api.add_resource(AgeTransitionNotificationResource, '/age_notifications', '/age_notifications/<int:notification_id>')

if __name__ == '__main__':
    app.run(port=5555)
