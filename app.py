#!/usr/bin/env python3
import os
from pytz import timezone
from datetime import timedelta, datetime
from apscheduler.schedulers.background import BackgroundScheduler
from requests.auth import HTTPBasicAuth
import requests
import cloudinary
from cloudinary.uploader import upload as cloudinary_upload
import base64
from sqlalchemy import func
from flask import Flask, request, jsonify, request
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, User, Student, School, Event, Payment,Youth, Attendance,bcrypt, update_student_categories, update_youth_categories, PasswordResetToken, update_completed_payments
from utils import generate_totp_secret, generate_totp_token, send_email
import africastalking

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
CONSUMER_KEY = os.environ.get('CONSUMER_KEY')
CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET')
BUSINESS_SHORTCODE = os.environ.get('BUSINESS_SHORTCODE')
PASSKEY = os.environ.get('PASSKEY')
AFRICATALKING_USERNAME = os.environ.get('AFRICATALKING_USERNAME')
AFRICATALKING_API_KEY = os.environ.get('AFRICATALKING_API_KEY')
# Initialize Africa's Talking SDK
africastalking.initialize(AFRICATALKING_USERNAME, AFRICATALKING_API_KEY)
sms = africastalking.SMS
cloudinary.config(
    cloud_name=os.environ.get('CLOUD_NAME'),
    api_key=os.environ.get('API_KEY'),
    api_secret=os.environ.get('API_SECRET')
)
app.json.compact = False
jwt = JWTManager(app)       
nairobi_tz = timezone('Africa/Nairobi')
migrate = Migrate(app, db)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)
def youth_update_yearly_payment(new_amount):
    """
    Update the yearly_payment_amount for all users who have completed a full year
    since their `year_created` date.
    """
    current_date = datetime.now(nairobi_tz)

    # Fetch all users who need their payments updated
    youths_to_update = Youth.query.all()

    for youth in youths_to_update:
        year_diff = current_date.year - youth.last_updated_at.year
        if year_diff >= 1:
            youth.is_active = False
            youth.yearly_payment_amount = new_amount
            youth.last_updated_at = datetime(current_date.year, 1, 1)
            send_email(
            youth.email, 
            "Payment Update", 
            f"Hello, {youth.name}, Happy new year. Your payment for this year is {new_amount}, KGGA Team" 
        )

    db.session.commit() 
def school_update_yearly_payment():
    """
    Update the yearly_payment_amount for all users who have completed a full year
    since their `year_created` date.
    """
    current_date = datetime.now(nairobi_tz)

    # Fetch all users who need their payments updated
    schools_to_update = School.query.all()

    for school in schools_to_update:
        year_diff = current_date.year - school.last_updated_at.year
        yearly_payment = school.calculate_yearly_payment()
        if year_diff >= 1:
            school.is_active = False
            school.yearly_payment_amount = yearly_payment
            school.last_updated_at = datetime(current_date.year, 1, 1)
            send_email(
            school.email, 
            "Payment Update", 
            f"Hello, {school.school_name}, Happy new year. Your payment for this year is {school.yearly_total_payment}, KGGA Team" 
        )

    db.session.commit() 

def schedule_yearly_tasks():
    """
    Schedule the yearly payment update tasks for youths and schools.
    """
    scheduler = BackgroundScheduler(timezone="Africa/Nairobi")
    
    # Schedule the youth payment update
    scheduler.add_job(
        func=lambda: youth_update_yearly_payment(new_amount=500.0),
        trigger="cron",
        month=1,
        day=1,
        hour=0,
        minute=0,
        id="youth_yearly_payment_update",
        replace_existing=True
    )
    
    # Schedule the school payment update
    scheduler.add_job(
        func=school_update_yearly_payment,
        trigger="cron",
        month=1,
        day=1,
        hour=0,
        minute=0,
        id="school_yearly_payment_update",
        replace_existing=True
    )
    
    scheduler.start()

@app.before_first_request
def start_scheduler():
    """
    Start the scheduler before the first request.
    """
    schedule_yearly_tasks()


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
        if user_id:
            user = User.query.get_or_404(user_id)
            update_completed_payments()
            return user.to_dict()
        else:
            users = User.query.all()
            update_completed_payments()
            return [user.to_dict() for user in users]
    

    def post(self):
        data = request.get_json()
        totp_secret = generate_totp_secret()
        user_token= generate_totp_token(totp_secret)
        email = data['email']
        new_user = User(
            name=data['name'],
            email=data['email'],
            phone_number=data['phone_number'],
            role=data['role'],
            password_hash=data['password'],
            token=generate_totp_secret()
        )
        send_email(email, "Your Admin Account has been Created", f"Use this as your Logins: {user_token}.\nTo set your password. Forget your password and follow the process")
        new_user.password_hash = user_token
        db.session.add(new_user)
        db.session.commit()
        return new_user.to_dict(), 201

    def patch(self, user_id):
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
            update_completed_payments()
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
        if youth_id:
            youth = Youth.query.get_or_404(youth_id)
            youth.update_youth_amounts()
            update_completed_payments()
            return youth.to_dict()
        else:
            youths = Youth.query.all()
            for youth in youths:
                youth.update_youth_amounts()
            update_completed_payments()
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
        send_email(email, "Your Youth Account has been Created", f"Use this as your Logins: {token}.\nTo set your password. Forget your password and follow the process")
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
        if school_id:
            school = School.query.get_or_404(school_id)
            school.set_yearly_payment()
            update_completed_payments()
            return school.to_dict()
        else:
            schools = School.query.all()
            for school in schools:
                school.set_yearly_payment()
            update_completed_payments()
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
        send_email(email, "Your School Account has been Created", f"Use this as your Logins: {token}.\nTo set your password. Forget your password and follow the process")
        new_school.password_hash = token
        db.session.add(new_school)
        db.session.commit()
        if new_school.school_type == 'Public':
            # Set the yearly payment amount (this can also be set in the model)
            # Create the payment record
            payment = Payment(
                amount=1000,
                status='completed',
                payment_method='GOV',
                payment_type='registration',
                school_id=new_school.id
            )
            
            # Add the payment record to the session and commit
            db.session.add(payment)
            db.session.commit()
        return new_school.to_dict(), 201

    def patch(self, school_id):
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
def event_emails(category,subject, body):
    # Retrieve the appropriate users based on the category
    if category == 'all':
        users_to_notify = Youth.query.all()+School.query.all()
    elif category == 'youth':
        users_to_notify = Youth.query.all()
    elif category == 'Young_Leader':
        users_to_notify = Youth.query.filter_by(category=category).all()
    elif category == 'Bravo':
        users_to_notify = Youth.query.filter_by(category=category).all()
    elif category == 'school':
        users_to_notify = School.query.all()
    else:
        users_to_notify = []
    
    for user in users_to_notify:
        send_email(user.email, subject, body) 
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
        data = request.form.to_dict()
        
        # Check if the required fields are present
        if not data.get('category'):    
            return {"error": "The 'category' field is required."}, 400

        image = request.files.get('image')
        if image:
            try:
                # Attempt to upload the image to Cloudinary
                upload_result = cloudinary_upload(
                    image, 
                    resource_type="image", 
                    transformation=[
                        {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                        {"fetch_format": "auto", "quality": "auto"}
                    ]
                )
                data['image'] = upload_result['secure_url']
            except Exception as e:
                # Handle Cloudinary upload error
                return {"error": "Image upload failed.", "details": str(e)}, 500

        # Validate category field
        category = data.get('category')
        if category not in ['all', 'school', 'youth', 'Young_Leader', 'Bravo']:
            return {"error": "Invalid category type. Choose from 'school', 'youth', 'Young_Leader', or 'Bravo'."}, 400

        try:
            # Create and save the new event in the database
            new_event = Event(**data)
            db.session.add(new_event)
            db.session.commit()
            
            if category in ['all','school', 'youth', 'Young_Leader', 'Bravo']:
                event_emails(category, subject = f"Created Event Notification: {new_event.title}", body = f"Dear user, \n\nThe {new_event.title} event has been Created. \n This event is for {new_event.category}\nTime is {new_event.event_date}\nFor more info login in to your account.\n\nBest regards,\nEvent Management Team")
        except Exception as e:
            # Handle any database errors
            db.session.rollback()
            return {"error": "Failed to create event.", "details": str(e)}, 500

        return new_event.to_dict(), 201

    def patch(self, event_id):
        # Attempt to retrieve the event, return 404 if not found
        event = Event.query.get_or_404(event_id)
        data = request.form.to_dict()
        image = request.files.get('image')

        # Attempt to upload a new image to Cloudinary if provided
        if image:
            try:
                upload_result = cloudinary_upload(
                    image,
                    resource_type="image",
                    transformation=[
                        {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                        {"fetch_format": "auto", "quality": "auto"}
                    ]
                )
                data['image'] = upload_result['secure_url']
            except Exception as e:
                return {"error": "Image upload failed.", "details": str(e)}, 500

        # Validate and set the category field if provided
        category = data.get('category')
        if category:
            if category not in ['all','school', 'youth', 'Young_Leader', 'Bravo']:
                return {"error": "Invalid category type. Choose from 'school', 'youth', 'Young_Leader', or 'Bravo'."}, 400
            event.category = category
        # Process each key-value pair in data for updating event attributes
        for key, value in data.items():
            if key == 'date':
                try:
                    # Attempt to parse and format the date field to %Y-%m-%dT%H:%M
                    parsed_date = datetime.strptime(value, "%Y-%m-%dT%H:%M")
                    setattr(event, key, parsed_date)
                except ValueError:
                    return {"error": f"Invalid date format for '{key}'. Expected format: %Y-%m-%dT%H:%M."}, 400
            elif key != 'category' and key != 'image':
                setattr(event, key, value)

        # Attempt to commit changes to the database
        try:
            db.session.commit()
            if event.category in ['all', 'school', 'youth', 'Young_Leader', 'Bravo']:
                event_emails(event.category, subject = f"Updated Event Notification: {event.title}", body = f"Dear user, \n\nThe {event.title} event has been updated. \n This is an event for {event.category}\nTime is {event.event_date}\nFor more info login in to your account.\n\nBest regards,\nEvent Management Team")
        except Exception as e:
            db.session.rollback()
            return {"error": "Failed to update event.", "details": str(e)}, 500

        return event.to_dict(), 200


    def delete(self, event_id):
        event = Event.query.get_or_404(event_id)
        db.session.delete(event)
        db.session.commit()
        return '', 204
class MarkAttendance(Resource):
    @jwt_required()
    def post(self, event_id):
        # Get the current user's ID and role from the JWT token
        current_user_id = get_jwt_identity()
        claims = get_jwt()  # Get the claims from the JWT token
        role = claims.get('role')  # Extract the role from the claims

        # Check if the event exists
        event = Event.query.get(event_id)
        if not event:
            return {"message": "Event not found"}, 404

        # Check if the user is a youth or school, and mark the attendance accordingly
        if role == 'youth':
            # Get the youth user
            youth = Youth.query.get(current_user_id)
            if not youth:
                return {"message": "Youth not found"}, 404

            # Check if the youth has already marked attendance for the event
            existing_attendance = Attendance.query.filter_by(event_id=event_id, youth_id=current_user_id).first()
            if existing_attendance:
                return {"message": "Attendance already marked for this event"}, 400

            # Create and record attendance for the youth
            attendance = Attendance(
                event_id=event_id,
                youth_id=current_user_id,
                attendance_date=datetime.now()
            )

        elif role == 'school':
            # Get the school user
            school = School.query.get(current_user_id)
            if not school:
                return {"message": "School not found"}, 404

            # Check if the school has already marked attendance for the event
            existing_attendance = Attendance.query.filter_by(event_id=event_id, school_id=current_user_id).first()
            if existing_attendance:
                return {"message": "Attendance already marked for this event"}, 400

            # Create and record attendance for the school
            attendance = Attendance(
                event_id=event_id,
                school_id=current_user_id,
                attendance_date=datetime.now()
            )

        else:
            return {"message": "Invalid role"}, 400

        # Add attendance to the session and commit
        db.session.add(attendance)
        db.session.commit()

        return {"message": "Attendance marked successfully", "attendance_id": attendance.id}, 201

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
        email_body = f"""
        <html>
            <body>
                <p>Dear {user.name or "User"},</p>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <p>
                    <a href="{reset_link}" style="color: #4CAF50; text-decoration: none; font-weight: bold;">
                        Reset Your Password
                    </a>
                </p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request a password reset, please ignore this email.</p>
                <br>
                <p>Best regards,<br>Your Support Team</p>
            </body>
        </html>
        """

        # Send the styled HTML email
        send_email(
            user.email, 
            "Password Reset Request", 
            email_body,
            content_type='html'  # Specify HTML format for the email
        )

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
    mpesa_merchant_request_id = stk_callback.get('MerchantRequestID')

    if result_code == 0:
        callback_metadata = stk_callback.get("CallbackMetadata", {}).get("Item", [])
        transaction_data = {item['Name']: item.get('Value') for item in callback_metadata}
        
        # Update payment record
        payment = Payment.query.filter_by(merchant_request_id = mpesa_merchant_request_id).first()
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
        payment.mpesa_receipt_number = result_desc
        db.session.commit()
        return jsonify({
            "status": "error",
            "message": result_desc
        }), 400

#Sending SMS
@app.route('/youth_send_sms', methods=['POST'])
def youth_send_sms():
    try:
        data = request.get_json()
        category = data.get('category', 'All')
        message = data.get('message', 'This is the default message body.')
        # Function to format phone numbers
        def format_phone_number(phone):
            """
            Convert '07xxxxxxxx' to '+2547xxxxxxxx' format.
            """
            if phone.startswith('07'):  # Check if number starts with '07'
                return '+254' + phone[1:]  # Replace '0' with '+254'
            elif phone.startswith('+254'):  # Already formatted
                return phone
            else:
                raise ValueError(f"Invalid phone number format: {phone}")
        # Determine the recipients based on the category
        if category == 'All':
            recipients = Youth.query.all()
        elif category in ['Membership', 'Technical', 'Finance', 'Executive']:
            # Filter by committee
            recipients = Youth.query.filter_by(commitee=category).all()
        elif category == 'Commissioner':
            # Filter by commissioner
            recipients = Youth.query.filter(Youth.commissioner.isnot(None)).all()
        else:
            # Filter by category
            recipients = Youth.query.filter_by(category=category).all()

        # Extract email addresses
        phone_numbers = [format_phone_number(youth.phone_number) for youth in recipients if youth.phone_number]
        
        # Validate input
        if not recipients or not message:
            return jsonify({"error": "Both 'recipients' and 'message' are required"}), 400
        # Send SMS
        response = sms.send(message, phone_numbers)
        
        return jsonify({
            "status": "success",
            "response": response
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/school_send_sms', methods=['POST'])
def school_send_sms():
    try:
        # Get data from request
        data = request.get_json()
        recipient_type = data.get('recipient_type', 'all')  # 'school', 'guide_leader', or 'all'
        message = data.get('message', 'This is a message notification.')

        phone_numbers = []

        # Function to format phone numbers
        def format_phone_number(phone):
            """
            Convert '07xxxxxxxx' to '+2547xxxxxxxx' format.
            """
            if phone.startswith('07'):  # Check if number starts with '07'
                return '+254' + phone[1:]  # Replace '0' with '+254'
            elif phone.startswith('+254'):  # Already formatted
                return phone
            else:
                raise ValueError(f"Invalid phone number format: {phone}")

        # Determine recipients based on the recipient_type parameter
        if recipient_type == 'school':
            # Collect only school phone numbers
            schools = School.query.all()
            phone_numbers = [format_phone_number(school.phone_number) for school in schools]

        elif recipient_type == 'guide_leader':
            # Collect only guide leader phone numbers
            guide_leaders = (
                db.session.query(Youth)
                .join(School, Youth.id == School.guide_leader_id)
                .filter(School.is_active == True)  # Adjust filters as needed
                .all()
            )
            phone_numbers = [format_phone_number(leader.phone_number) for leader in guide_leaders]

        elif recipient_type == 'all':
            # Collect both school and guide leader phone numbers
            schools = School.query.all()
            guide_leaders = (
                db.session.query(Youth)
                .join(School, Youth.id == School.guide_leader_id)
                .filter(School.is_active == True)
                .all()
            )
            phone_numbers = (
                [format_phone_number(school.phone_number) for school in schools] +
                [format_phone_number(leader.phone_number) for leader in guide_leaders]
            )
        
        # Validate input
        if not phone_numbers or not message:
            return jsonify({"error": "Both 'recipients' and 'message' are required"}), 400
        # Send SMS
        response = sms.send(message, phone_numbers)
        
        return jsonify({
            "status": "success",
            "response": response
        }), 200
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    elif category in ['Membership', 'Technical', 'Finance', 'Executive']:
        # Filter by committee
        recipients = Youth.query.filter_by(commitee=category).all()
    elif category == 'Commissioner':
        # Filter by commissioner
        recipients = Youth.query.filter(Youth.commissioner.isnot(None)).all()
    else:
        # Filter by category
        recipients = Youth.query.filter_by(category=category).all()

    # Extract email addresses
    emails = [youth.email for youth in recipients if youth.email]

    # Create and send the email
    if not emails:
        return jsonify({"message": "No recipients found for the specified category."}), 404

    # Create and send the email
    for email in emails:
        try:
            send_email(email, subject, message_body)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"message": "Emails sent successfully!"}), 200

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
    return jsonify({"message": "Emails sent successfully!"}), 200
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
api.add_resource(MarkAttendance, '/events/<int:event_id>/attend')
api.add_resource(PaymentResource, '/payments', '/payments/<int:payment_id>')
api.add_resource(ForgotPassword, '/forgot-password')
api.add_resource(ResetPassword, '/reset-password')

if __name__ == '__main__':
    app.run(port=5555)