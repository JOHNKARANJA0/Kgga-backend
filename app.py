#!/usr/bin/env python3
import os
from datetime import timedelta, datetime
import pyotp
from requests.auth import HTTPBasicAuth
import requests
import base64
from sqlalchemy import func
from flask import Flask, request, jsonify, request
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, User, Student, School, Event, Payment,Youth, bcrypt, update_student_categories, update_youth_categories, PasswordResetToken, update_completed_payments
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
# M-PESA credentials
CONSUMER_KEY = 'xem7gGqhAUa8ueAItC33JsWTnXpRjA0X8feF7yPBjc8ZfDQD'
CONSUMER_SECRET = 'TPLkVjP8JeCS9rdA0hSuFzGh9rSMkUgBpemOlrdgDFSsiFPLpgGhA3DGHGdJmc4h'
BUSINESS_SHORTCODE = '174379'
PASSKEY = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'
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
        update_completed_payments()
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
        update_completed_payments()
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
        update_completed_payments()
        if student_id:
            update_student_categories()
            student = Student.query.get_or_404(student_id)
            return student.to_dict()
        else:
            students = Student.query.all()
            return [student.to_dict() for student in students]

    def post(self):
        data = request.get_json()
        if 'dob' in data:
            try:
                # Parse 'dob' to a date object, ensuring it's in the correct format for SQLite
                data['dob'] = datetime.strptime(data['dob'], '%Y-%m-%d').date()
            except ValueError:
                # If 'dob' is not in the correct format, return an error message
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400
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
        update_completed_payments()
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
        totp_secret = generate_totp_secret()
        token= generate_totp_token(totp_secret)
        email = data['email']
        new_youth = Youth(
            **data
        )
        send_email(email, "Your Youth Account has been Created", f"Use this as your Logins: {token}")
        new_youth.password_hash = token
        db.session.add(new_youth)
        db.session.commit()
        response_data = new_youth.to_dict()
        return response_data, 201
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
        update_completed_payments()
        if school_id:
            school = School.query.get_or_404(school_id)
            return school.to_dict()
        else:
            schools = School.query.all()
            return [school.to_dict() for school in schools]

    def post(self):
        data = request.get_json()
        totp_secret = generate_totp_secret()
        token= generate_totp_token(totp_secret)
        email = data['email']
        students_data = data.get('students', [])
        for student in students_data:
            if 'dob' in student:
                # Convert the dob from string to a Python date object
                student['dob'] = datetime.strptime(student['dob'], '%Y-%m-%d').date()
        students = [Student(**student) for student in students_data]
        data['students'] = students
        new_school = School(**data)
        send_email(email, "Your Youth Account has been Created", f"Use this as your Logins: {token}")
        new_school.password_hash = token
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

class ForgotPassword(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')

        # Find the user by email
        user = User.query.filter_by(email=email).first() or \
               Youth.query.filter_by(email=email).first() or \
               School.query.filter_by(email=email).first()

        if not user:
            return {"error": "User not found."}, 404

        totp_secret = generate_totp_secret() 
        token = generate_totp_token(totp_secret)
        expiration_time = datetime.now() + timedelta(hours=1)
        password_reset = PasswordResetToken(
            email=user.email,
            token=token,
            expires_at=expiration_time
        )
        db.session.add(password_reset)
        db.session.commit()
        reset_link = f"https://voluble-kelpie-0d72d6.netlify.app/reset-password?token={token}&email={user.email}"
        send_email(user.email, "Password Reset Request", f"Reset your password by clicking this link: {reset_link}")

        return {"message": "Password reset email sent."}, 200
    
    
class ResetPassword(Resource):
    def post(self):
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        reset_token = PasswordResetToken.query.filter_by(token=token).first()

        if not reset_token:
            return {"error": "Invalid or expired token."}, 401
        if reset_token.expires_at < datetime.now():
            return {"error": "Token has expired."}, 401
        user = User.query.filter_by(email=reset_token.email).first() or \
               Youth.query.filter_by(email=reset_token.email).first() or \
               School.query.filter_by(email=reset_token.email).first()

        if not user:
            return {"error": "User not found."}, 404
        user.password_hash = new_password
        db.session.commit()
        db.session.delete(reset_token)
        db.session.commit()

        return {"message": "Password has been reset successfully."}, 200
    


def generate_access_token():
    """Generate M-PESA API access token"""
    url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    response = requests.get(url, auth=HTTPBasicAuth(CONSUMER_KEY, CONSUMER_SECRET))
    return response.json().get('access_token')

def initiate_stk_push(payment):
    """Initiate STK push request"""
    access_token = generate_access_token()
    url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    headers = {'Authorization': f'Bearer {access_token}'}

    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f"{BUSINESS_SHORTCODE}{PASSKEY}{timestamp}".encode()).decode('utf-8')

    payload = {
        "BusinessShortCode": BUSINESS_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(payment.amount),
        "PartyA": payment.phone_number,
        "PartyB": BUSINESS_SHORTCODE,
        "PhoneNumber": payment.phone_number,
        "CallBackURL": "https://kgga-backend.onrender.com/callback",
        "AccountReference": payment.transaction_id,
        "TransactionDesc": f"Payment for {payment.payment_type}"
    }

    response = requests.post(url, json=payload, headers=headers)
    return response.json()

@app.route('/initiate-payment', methods=['POST'])
def start_payment():
    """Endpoint to initiate payment"""
    try:
        data = request.get_json()
        
        # Create new payment record
        payment = Payment(
            amount=data['amount'],
            phone_number=data['phone_number'],
            payment_type=data['payment_type'],
            youth_id=data.get('youth_id'),
            school_id=data.get('school_id'),
            transaction_id=Payment.generate_transaction_id()
        )
        
        db.session.add(payment)
        db.session.commit()
        
        # Initiate M-PESA STK push
        result = initiate_stk_push(payment)
        merchant_request_id = result.get("MerchantRequestID")
        if merchant_request_id:
            payment.merchant_request_id = merchant_request_id
            db.session.commit()
        return jsonify(result), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/callback', methods=['POST'])
def mpesa_callback():
    """Callback endpoint for M-PESA"""
    data = request.json
    stk_callback = data.get("Body", {}).get("stkCallback", {})
    result_code = stk_callback.get("ResultCode")
    result_desc = stk_callback.get("ResultDesc")

    if result_code == 0:
        callback_metadata = stk_callback.get("CallbackMetadata", {}).get("Item", [])
        transaction_data = {item['Name']: item.get('Value') for item in callback_metadata}
        
        # Update payment record
        payment = Payment.query.filter_by(merchant_request_id=stk_callback.get('MerchantRequestID')).first()
        if payment:
            payment.status = 'completed'
            payment.mpesa_receipt_number = transaction_data.get('MpesaReceiptNumber')
            payment.process_payment()
            db.session.commit()
            
        return jsonify({
            "status": "success",
            "transaction": transaction_data
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": result_desc
        }), 400
#Sending emails
@app.route('/send-youth-email', methods=['POST'])
def send_email_to_category():
    data = request.get_json()
    category = data.get('category', 'All')
    subject = data.get('subject', 'Default Subject')
    message_body = data.get('message', 'This is the default message body.')

    # Determine the recipients based on the category
    if category == 'All':
        recipients = Youth.query.all()
    else:
        recipients = Youth.query.filter_by(category=category).all()

    # Extract email addresses
    emails = [youth.email for youth in recipients if youth.email]

    if not emails:
        return jsonify({"message": "No recipients found for the specified category."}), 404

    # Create and send the email
    for email in emails:
        try:
            send_email(email,subject,message_body)
            return jsonify({"message": "Emails sent successfully!"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/send-school-email', methods=['POST'])
def send_email_to_schools_or_leaders():
    data = request.get_json()
    recipient_type = data.get('recipient_type', 'all')  # 'school', 'guide_leader', or 'all'
    subject = data.get('subject', 'Notification')
    message_body = data.get('message', 'This is a message notification.')

    emails = []

    # Determine recipients based on the recipient_type parameter
    if recipient_type == 'school':
        # Collect only school emails
        schools = School.query.all()
        emails = [school.email for school in schools]

    elif recipient_type == 'guide_leader':
        # Collect only guide leader emails
        guide_leaders = (
            db.session.query(Youth)
            .join(School, Youth.id == School.guide_leader_id)
            .filter(School.is_active == True)  # Adjust filters as needed
            .all()
        )
        emails = [leader.email for leader in guide_leaders]

    elif recipient_type == 'all':
        # Collect both school and guide leader emails
        schools = School.query.all()
        guide_leaders = (
            db.session.query(Youth)
            .join(School, Youth.id == School.guide_leader_id)
            .filter(School.is_active == True)
            .all()
        )
        emails = [school.email for school in schools] + [leader.email for leader in guide_leaders]

    # Check if there are any recipients
    if not emails:
        return jsonify({"message": "No recipients found for the specified type."}), 404

    # Try sending the email to all collected recipients
    for email in emails:
        try:
            send_email(email,subject,message_body)
            return jsonify({"message": f"Emails sent successfully to {recipient_type}!"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
@app.route('/reports/youths', methods=['GET'])
def generate_youth_report():
    # Query for total payment and individual payments for each youth
    report_data = db.session.query(
        Youth.id,
        Youth.name,
        Youth.category,
        Youth.registration_fee,
        Youth.payment_status,
        Youth.yearly_payment_amount,
        Youth.yearly_total_payment,
        Youth.membership_no,
        func.sum(Payment.amount).label('total_paid'),
        func.count(Payment.id).label('total_payments')
    ).join(Payment, Youth.id == Payment.youth_id).group_by(Youth.id).all()

    # Format the report data
    report = []
    for youth in report_data:
        report.append({
            'youth_id': youth.id,
            'name': youth.name,
            'category': youth.category,
            'Amount_Remaining': youth.yearly_payment_amount,
            'Amount_needed': youth.yearly_total_payment,
            'Membership_no': youth.membership_no,
            'registration_fee': youth.registration_fee,
            'payment_status': youth.payment_status,
            'total_paid': youth.total_paid,
            'total_payments': youth.total_payments
        })

    return jsonify(report)
@app.route('/reports/schools', methods=['GET'])
def generate_school_report():
    # Query for total payments per school
    report_data = db.session.query(
        School.id,
        School.school_name,
        School.yearly_payment_amount,
        School.yearly_total_payment,
        func.sum(Payment.amount).label('total_paid'),
        func.count(Student.id).label('student_count'),
        func.count(Payment.id).label('total_payments'),
        func.sum(Payment.amount).filter(Payment.payment_type == 'registration').label('regestration_payment'),
        func.sum(Payment.amount).filter(Payment.payment_type == 'yearly').label('yearly_payment'),
        func.count(Payment.status).filter(Payment.status == 'completed').label('completed_payments'),
        func.count(Payment.status).filter(Payment.status == 'pending').label('pending_payments')
    ).join(Payment, School.id == Payment.school_id)\
    .outerjoin(Student, School.id == Student.school_id)\
    .group_by(School.id).all()
    
    total_schools = db.session.query(func.count(School.id)).scalar()

    # Format the report data
    report = []
    for school in report_data:
        report.append({
            'school_id': school.id,
            'school_name': school.school_name,
            'student_count': school.student_count,
            "Amount_needed": school.yearly_total_payment,
            'Amount_Remaining': school.yearly_payment_amount,
            'total_paid': school.total_paid,
            "regestration_payment":  school.regestration_payment,
            'yearly_payment':school.yearly_payment,
            'total_payments': school.total_payments,
            'completed_payments': school.completed_payments,
            'pending_payments': school.pending_payments
        })

    return jsonify({
        'total_schools': total_schools,
        'school_reports': report
    })
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
api.add_resource(ForgotPassword, '/forgot-password')
api.add_resource(ResetPassword, '/reset-password')

if __name__ == '__main__':
    app.run(port=5555)