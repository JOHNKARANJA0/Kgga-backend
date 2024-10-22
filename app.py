#!/usr/bin/env python3
import os
from datetime import timedelta, datetime
import pyotp
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, User, Student, School, Event, Payment, FinancialReport, Youth, bcrypt, update_student_categories, update_youth_categories, generate_financial_report
from utils import generate_totp_secret, generate_totp_token, send_email

app = Flask(__name__)
CORS(app, resources={r"/*": {
    "origins": "*",
    "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
}})
app.config['SQLALCHEMY_DATABASE_URI'] =os.environ.get('DATABASE_URI') #'sqlite:///app.db' 
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
from flask import request
from flask_restful import Resource
from flask_jwt_extended import create_access_token

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        email = request_json.get('email')
        password = request_json.get('password')

        # Try to authenticate with each model
        for model, role in [(User, "user"), (Youth, "youth"), (School, "school")]:
            entity = model.query.filter_by(email=email).first()
            if entity and entity.authenticate(password):
                access_token = create_access_token(identity=entity.id, additional_claims={"role": role})
                return {"access_token": access_token, "role": role}, 200

        return {"message": "Invalid email or password"}, 401


class CheckSession(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        claims = get_jwt()  # Get the claims from the JWT token
        role = claims.get('role')  # Extract the role from the claims

        if role == 'user':
            user = User.query.get(current_user_id)
            if user:
                return user.to_dict(), 200
            else:
                return {"error": "User not found"}, 404

        elif role == 'youth':
            youth = Youth.query.get(current_user_id)
            if youth:
                return youth.to_dict(), 200
            else:
                return {"error": "Youth not found"}, 404

        elif role == 'school':
            school = School.query.get(current_user_id)
            if school:
                return school.to_dict(), 200
            else:
                return {"error": "School not found"}, 404

        return {"error": "Invalid role"}, 400
    
BLACKLIST = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, decrypted_token):
    return decrypted_token['jti'] in BLACKLIST


class Logout(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()

        user = User.query.get(current_user_id) or Youth.query.get(current_user_id) or School.query.get(current_user_id)

        if user:
            db.session.commit()

        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"success": "Successfully logged out"}, 200

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
            password_hash=data['password'],
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
            update_student_categories()
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

# Youth resource for CRUD operations
class YouthResource(Resource):
    def get(self, youth_id=None):
        if youth_id:
            update_youth_categories()
            youth = Youth.query.get_or_404(youth_id)
            return youth.to_dict()
        else:
            update_youth_categories()
            youths = Youth.query.all()
            return [youth.to_dict() for youth in youths]

    def post(self):
        data = request.get_json()
        if 'dob' in data:
            try:
                data['dob'] = datetime.strptime(data['dob'], '%Y-%m-%d').date()
            except ValueError:
                return {"error": "Invalid date format. Use YYYY-MM-DD."}, 400
        if 'password' not in data:
            return {"error": "Password is required."}, 400
        new_youth = Youth(
            **data,
            password_hash=bcrypt.generate_password_hash(data['password']).decode('utf-8')
        )
        db.session.add(new_youth)
        db.session.commit()
        return new_youth.to_dict(), 201

    def put(self, youth_id):
        youth = Youth.query.get_or_404(youth_id)
        data = request.get_json()
        for key, value in data.items():
            if key == 'dob':
                try:
                    value = datetime.strptime(value, '%Y-%m-%d').date()
                except ValueError:
                    return {"error": "Invalid date format. Use YYYY-MM-DD."}, 400
            setattr(youth, key, value)
        db.session.commit()
        return youth.to_dict(), 200

    def delete(self, youth_id):
        youth = Youth.query.get_or_404(youth_id)
        db.session.delete(youth)
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

# Financial Report resource for CRUD operations
class FinancialReportResource(Resource):
    def get(self, report_id=None):
        if report_id:
            generate_financial_report()
            report = FinancialReport.query.get_or_404(report_id)
            return report.to_dict()
        else:
            generate_financial_report()
            reports = FinancialReport.query.all()
            return [report.to_dict() for report in reports]

    def post(self):
        data = request.get_json()
        new_report = FinancialReport(**data)
        db.session.add(new_report)
        db.session.commit()
        return new_report.to_dict(), 201

    def put(self, report_id):
        report = FinancialReport.query.get_or_404(report_id)
        data = request.get_json()
        for key, value in data.items():
            setattr(report, key, value)
        db.session.commit()
        return report.to_dict()

    def delete(self, report_id):
        report = FinancialReport.query.get_or_404(report_id)
        db.session.delete(report)
        db.session.commit()
        return '', 204
class ForgotPassword(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')

        # Find the user by email
        user = User.query.filter_by(email=email).first() or \
               Youth.query.filter_by(email=email).first() or \
               School.query.filter_by(email=email).first()

        if not user:
            return {"message": "User not found."}, 404

        # Generate password reset token
        token = generate_totp_token(email)

        # Send email with reset link (you'll need to implement send_email)
        reset_link = f"http://yourfrontend.com/reset-password?token={token}"
        send_email(user.email, "Password Reset Request", f"Reset your password by clicking this link: {reset_link}")

        return {"message": "Password reset email sent."}, 200
    
class ResetPassword(Resource):
    def post(self):
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')

        # Decode the token
        try:
            email = get_jwt_identity(token)
        except Exception as e:
            return {"message": "Invalid or expired token."}, 401

        # Find the user by email
        user = User.query.filter_by(email=email).first() or \
               Youth.query.filter_by(email=email).first() or \
               School.query.filter_by(email=email).first()

        if not user:
            return {"message": "User not found."}, 404

        # Update password
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()

        return {"message": "Password has been reset successfully."}, 200
# Routes
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')

api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(StudentResource, '/students', '/students/<int:student_id>')
api.add_resource(YouthResource, '/youths', '/youths/<int:youth_id>')
api.add_resource(SchoolResource, '/schools', '/schools/<int:school_id>')
api.add_resource(EventResource, '/events', '/events/<int:event_id>')
api.add_resource(PaymentResource, '/payments', '/payments/<int:payment_id>')
api.add_resource(FinancialReportResource, '/financial_reports', '/financial_reports/<int:report_id>')
api.add_resource(ForgotPassword, '/forgot-password')
api.add_resource(ResetPassword, '/reset-password')

if __name__ == '__main__':
    app.run(port=5555)